import hashlib
import csv
import json
import math
import os
import re
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


FEATURES = (
    "failed_login_count", "successful_login_count", "sudo_count", "process_count",
    "network_connection_count", "unique_destination_ip_count", "file_event_count", "cron_event_count",
)
CATEGORY_FEATURES = {
    "authentication": ("failed_login_count", "successful_login_count"),
    "privilege_escalation": ("sudo_count",), "process": ("process_count",),
    "network": ("network_connection_count", "unique_destination_ip_count"),
    "file": ("file_event_count",), "cron": ("cron_event_count",),
}
DEFAULT_CONFIG = {
    "window_seconds": 60, "baseline_path": "receiver/data/baseline.json",
    "baseline_seed_path": "data/training_data.csv", "baseline_min_samples": 30,
    "baseline_z_threshold": 2.5, "correlation_z_threshold": 2.5, "correlation_pair_weight": 0.12,
    "correlation_category_weight": 0.08, "ml_score_scale": 8.0,
    "risk_weights": {"ml": 0.35, "statistical": 0.40, "correlation": 0.25},
    "thresholds": {"suspicious": 0.55, "critical": 0.82},
    "related_pairs": [["authentication", "privilege_escalation"], ["authentication", "process"],
        ["privilege_escalation", "process"], ["process", "network"], ["file", "process"],
        ["cron", "process"], ["cron", "network"]],
    "evidence": {"endpoint_env": "GHOSTWARE_MINIO_ENDPOINT", "access_key_env": "GHOSTWARE_MINIO_ACCESS_KEY",
        "secret_key_env": "GHOSTWARE_MINIO_SECRET_KEY", "bucket": "ghostware-evidence", "secure": True,
        "ledger_path": "receiver/data/integrity_ledger.jsonl"},
    "model_path": "model/anomaly_model.pkl",
}


def load_config(path=None):
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    config_path = Path(path or Path(__file__).with_name("detection_config.json"))
    if config_path.exists():
        supplied = json.loads(config_path.read_text(encoding="utf-8"))
        for key, value in supplied.items():
            if isinstance(value, dict) and isinstance(config.get(key), dict):
                config[key].update(value)
            else:
                config[key] = value
    return config


def _parse_timestamp(value):
    if value is None or value == "":
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    value = str(value).strip()
    try:
        return datetime.fromtimestamp(float(value), timezone.utc)
    except ValueError:
        pass
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def normalize_event(event):
    if not isinstance(event, dict):
        raise ValueError("Each telemetry message must be a JSON object")
    normalized = dict(event)
    metadata = event.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    normalized["host"] = str(event.get("host") or event.get("hostname") or "unknown")
    normalized["username"] = event.get("username") or metadata.get("username")
    normalized["timestamp"] = _parse_timestamp(event.get("timestamp")).isoformat()
    return normalized


class FeatureExtractor:
    """Converts collector-specific payloads into the shared feature schema."""

    def extract(self, event):
        data = event.get("event", {})
        data = data if isinstance(data, dict) else {"message": str(data)}
        source = str(event.get("source") or event.get("category") or event.get("type") or "").lower()
        event_type = str(event.get("event_type") or "").lower()
        raw_text = str(event.get("raw") or "").lower()
        message = str(data.get("message") or event.get("message") or "")
        if not message and not source and not event_type:
            message = raw_text
        text = re.sub(r"[_-]+", " ", f"{source} {event_type} {message}").lower()
        authentication_text = f"{text} {raw_text}"
        delta = {feature: 0.0 for feature in FEATURES}
        categories = set()
        explicit_features = event.get("features")
        if isinstance(explicit_features, dict):
            for feature in FEATURES:
                try:
                    value = float(explicit_features.get(feature, 0))
                except (TypeError, ValueError):
                    raise ValueError(f"Feature {feature} must be numeric")
                if not math.isfinite(value) or value < 0:
                    raise ValueError(f"Feature {feature} must be a finite non-negative number")
                delta[feature] = value
            categories.update(category for category, names in CATEGORY_FEATURES.items()
                if any(delta[name] > 0 for name in names))
            return delta, categories, self._destination_ip(event, data)

        if any(token in authentication_text for token in ("authentication", "ssh", "login", "pam", "password")):
            categories.add("authentication")
            if any(token in authentication_text for token in ("failed", "failure", "invalid user", "authentication error")):
                delta["failed_login_count"] = 1
            elif any(token in authentication_text for token in ("accepted", "successful", "login success", "session opened")):
                delta["successful_login_count"] = 1
        if any(token in f"{text} {raw_text}" for token in ("sudo", "privilege", "polkit")):
            categories.add("privilege_escalation")
            delta["sudo_count"] = 1
        if any(token in text for token in ("process", "execve", "command")):
            categories.add("process")
            delta["process_count"] = 1
        if any(token in text for token in ("network", "connection", "tcp", "udp", "dns")):
            categories.add("network")
            delta["network_connection_count"] = 1
        if any(token in text for token in ("file", "audit", "inode", "path=")):
            categories.add("file")
            delta["file_event_count"] = 1
        if any(token in text for token in ("cron", "crond", "scheduled task")):
            categories.add("cron")
            delta["cron_event_count"] = 1
        destination_ip = self._destination_ip(event, data)
        if destination_ip:
            categories.add("network")
            delta["network_connection_count"] = max(1, delta["network_connection_count"])
        return delta, categories, destination_ip

    @staticmethod
    def _destination_ip(event, data):
        metadata = event.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        event_context = " ".join(str(event.get(key) or "")
            for key in ("source", "category", "type", "event_type")).lower()
        is_network_event = any(token in event_context for token in ("network", "connection", "tcp", "udp", "dns"))
        candidate = (data.get("destination_ip") or data.get("dst_ip") or event.get("destination_ip")
            or metadata.get("destination_ip") or metadata.get("dst_ip") or metadata.get("ipv4_dst")
            or metadata.get("ipv6_dst"))
        if candidate:
            return str(candidate)
        if is_network_event:
            candidate = event.get("remote_ip") or metadata.get("remote_ip")
            if candidate:
                return str(candidate)
        elif event_context.strip():
            return None
        message = str(data.get("message") or event.get("message") or event.get("raw") or "")
        return next(iter(re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", message)), None)


class RollingWindowAggregator:
    def __init__(self, window_seconds):
        self.window = timedelta(seconds=window_seconds)
        self.host_events = defaultdict(list)
        self.lock = threading.RLock()

    def add(self, event, delta, categories, destination_ip):
        timestamp = _parse_timestamp(event["timestamp"])
        host = event["host"]
        with self.lock:
            rows = self.host_events[host]
            rows.append((timestamp, delta, categories, destination_ip, event))
            cutoff = timestamp - self.window
            rows[:] = [row for row in rows if row[0] >= cutoff]
            totals = {feature: 0.0 for feature in FEATURES}
            active_categories = set()
            destinations = set()
            for _, row_delta, row_categories, ip, _ in rows:
                active_categories.update(row_categories)
                if ip:
                    destinations.add(ip)
                for feature in FEATURES:
                    totals[feature] += row_delta.get(feature, 0.0)
            totals["unique_destination_ip_count"] = max(totals["unique_destination_ip_count"], float(len(destinations)))
            return totals, active_categories, [row[4] for row in rows]


class StatisticalBaseline:
    """Online Welford statistics, persisted and updated only with NORMAL windows."""

    def __init__(self, path, min_samples, seed_path=None):
        self.path = Path(path)
        self.min_samples = int(min_samples)
        self.count = 0
        self.means = {feature: 0.0 for feature in FEATURES}
        self.m2 = {feature: 0.0 for feature in FEATURES}
        self.lock = threading.RLock()
        self._load()
        if self.count == 0 and seed_path:
            self._seed(Path(seed_path))

    def _seed(self, seed_path):
        try:
            with seed_path.open(newline="", encoding="utf-8") as seed_file:
                for row in csv.DictReader(seed_file):
                    values = {feature: float(row[feature]) for feature in FEATURES}
                    if all(math.isfinite(value) and value >= 0 for value in values.values()):
                        self._update_memory(values)
            self._save()
        except (OSError, KeyError, TypeError, ValueError):
            return

    def _load(self):
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            self.count = int(saved["count"])
            self.means.update(saved["means"])
            self.m2.update(saved["m2"])
        except (FileNotFoundError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return

    def z_scores(self, values):
        with self.lock:
            if self.count < self.min_samples:
                return {feature: 0.0 for feature in FEATURES}
            scores = {}
            for feature in FEATURES:
                variance = self.m2[feature] / max(1, self.count - 1)
                scores[feature] = abs(values[feature] - self.means[feature]) / math.sqrt(max(variance, 1e-9))
            return scores

    def update(self, values):
        with self.lock:
            self._update_memory(values)
            self._save()

    def _update_memory(self, values):
        self.count += 1
        for feature in FEATURES:
            difference = values[feature] - self.means[feature]
            self.means[feature] += difference / self.count
            self.m2[feature] += difference * (values[feature] - self.means[feature])

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps({"count": self.count, "means": self.means, "m2": self.m2}), encoding="utf-8")
        temporary.replace(self.path)


class StatisticalDetector:
    def __init__(self, baseline, z_threshold):
        self.baseline = baseline
        self.z_threshold = float(z_threshold)

    def score(self, features):
        z_scores = self.baseline.z_scores(features)
        strongest = max(z_scores.values(), default=0.0)
        return max(0.0, min(1.0, (strongest - self.z_threshold) / max(strongest, 1.0))), z_scores


class IsolationForestDetector:
    def __init__(self, model_path, score_scale):
        self.model = None
        self.score_scale = float(score_scale)
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Trained Isolation Forest model not found: {path}")
        import joblib
        self.model = joblib.load(path)

    def predict(self, features):
        import pandas as pd
        row = pd.DataFrame([[features[feature] for feature in FEATURES]], columns=FEATURES)
        print("[MODEL INPUT]")
        for feature in FEATURES:
            print(f"{feature} = {features[feature]}")
        prediction_label = int(self.model.predict(row)[0])
        decision = float(self.model.decision_function(row)[0])
        scaled = max(-60.0, min(60.0, -decision * self.score_scale))
        ml_score = 1.0 / (1.0 + math.exp(-scaled))
        prediction = "ANOMALY" if prediction_label == -1 else "NORMAL"
        print("[MODEL OUTPUT]")
        print(f"prediction = {prediction} (label={prediction_label})")
        print(f"anomaly_score = {decision:.6f}")
        return prediction, decision, ml_score

    def score(self, features):
        return self.predict(features)[2]


class CorrelationEngine:
    def __init__(self, config):
        self.config = config

    def score(self, z_scores):
        threshold = float(self.config["correlation_z_threshold"])
        severity = {}
        for category, features in CATEGORY_FEATURES.items():
            strongest = max((z_scores.get(name, 0.0) for name in features), default=0.0)
            severity[category] = max(0.0, min(1.0, (strongest - threshold) / 4.0))
        active = {category for category, value in severity.items() if value > 0}
        score = sum(severity.values()) * float(self.config["correlation_category_weight"])
        for left, right in self.config["related_pairs"]:
            if left in active and right in active:
                score += float(self.config["correlation_pair_weight"]) * min(severity[left], severity[right])
        return max(0.0, min(1.0, score)), severity


class RiskEngine:
    def __init__(self, weights, thresholds):
        self.weights = weights
        self.thresholds = thresholds

    def assess(self, ml_score, statistical_score, correlation_score):
        total_weight = sum(float(weight) for weight in self.weights.values()) or 1.0
        score = (float(ml_score) * float(self.weights.get("ml", 0))
            + float(statistical_score) * float(self.weights.get("statistical", 0))
            + float(correlation_score) * float(self.weights.get("correlation", 0))) / total_weight
        if score >= float(self.thresholds["critical"]):
            level = "CRITICAL"
        elif score >= float(self.thresholds["suspicious"]):
            level = "SUSPICIOUS"
        else:
            level = "NORMAL"
        return max(0.0, min(1.0, score)), level


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class IntegrityLedger:
    """Local append-only hash chain for evidence references and SHA-256 values."""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def append(self, reference, evidence_sha256):
        with self.lock:
            entries = self._read_entries()
            previous_hash = entries[-1]["entry_hash"] if entries else "0" * 64
            entry = {"reference": reference, "evidence_sha256": evidence_sha256,
                "previous_hash": previous_hash, "recorded_at": datetime.now(timezone.utc).isoformat()}
            entry["entry_hash"] = hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as ledger_file:
                ledger_file.write(_canonical_json(entry) + "\n")
            return entry

    def verify(self):
        previous_hash = "0" * 64
        try:
            for entry in self._read_entries():
                recorded_hash = entry.pop("entry_hash")
                if entry.get("previous_hash") != previous_hash:
                    return False
                expected_hash = hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()
                if recorded_hash != expected_hash:
                    return False
                previous_hash = recorded_hash
            return True
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False

    def contains(self, reference, evidence_sha256):
        try:
            return any(entry.get("reference") == reference and entry.get("evidence_sha256") == evidence_sha256
                for entry in self._read_entries())
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def _read_entries(self):
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]


class MinioEvidenceStore:
    def __init__(self, config):
        endpoint = os.getenv(config["endpoint_env"])
        access_key = os.getenv(config["access_key_env"])
        secret_key = os.getenv(config["secret_key_env"])
        if not all((endpoint, access_key, secret_key)):
            raise RuntimeError("MinIO evidence storage is not configured")
        from minio import Minio
        self.client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=bool(config["secure"]))
        self.bucket = config["bucket"]
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def store(self, key, payload):
        from io import BytesIO
        content = _canonical_json(payload).encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        self.client.put_object(self.bucket, key, BytesIO(content), len(content), content_type="application/json")
        return f"{self.bucket}/{key}", digest

    def verify(self, reference, expected_sha256):
        bucket, key = reference.split("/", 1)
        response = self.client.get_object(bucket, key)
        try:
            return hashlib.sha256(response.read()).hexdigest() == expected_sha256
        finally:
            response.close()
            response.release_conn()


class DetectionPipeline:
    def __init__(self, config=None, model=None, evidence_store=None):
        self.config = config or load_config()
        root = Path(__file__).resolve().parent.parent
        def resolve(path):
            candidate = Path(path)
            return candidate if candidate.is_absolute() else root / candidate
        self.extractor = FeatureExtractor()
        self.aggregator = RollingWindowAggregator(self.config["window_seconds"])
        self.baseline = StatisticalBaseline(resolve(self.config["baseline_path"]),
            self.config["baseline_min_samples"], resolve(self.config.get("baseline_seed_path", "")))
        self.statistical = StatisticalDetector(self.baseline, self.config["baseline_z_threshold"])
        self.ml = IsolationForestDetector(resolve(self.config["model_path"]), self.config["ml_score_scale"])
        if model is not None:
            self.ml.model = model
        self.correlation = CorrelationEngine(self.config)
        self.risk = RiskEngine(self.config["risk_weights"], self.config["thresholds"])
        self.ledger = IntegrityLedger(resolve(self.config["evidence"]["ledger_path"]))
        self.evidence_store = evidence_store
        self.lock = threading.RLock()

    def process(self, event):
        with self.lock:
            normalized = normalize_event(event)
            local_ip = normalized.get("local_ip")
            remote_ip = normalized.get("remote_ip")
            if local_ip and remote_ip and local_ip != remote_ip:
                return {"status": "ANOMALY", "risk_level": "HIGH",
                    "reason": "LOCAL_REMOTE_IP_MISMATCH", "username": normalized.get("username"),
                    "local_ip": local_ip, "remote_ip": remote_ip, "action": "BLOCK_REMOTE_IP"}
            delta, event_categories, destination_ip = self.extractor.extract(normalized)
            features, _, window_events = self.aggregator.add(normalized, delta, event_categories, destination_ip)
            failed_login_count = int(features["failed_login_count"])
            if failed_login_count > 10:
                return {"status": "ANOMALY", "reason": "EXCESSIVE_FAILED_LOGINS",
                    "username": normalized.get("username"), "local_ip": local_ip, "remote_ip": remote_ip,
                    "failed_login_count": failed_login_count, "action": "BLOCK_IP"}
            statistical_score, z_scores = self.statistical.score(features)
            prediction, anomaly_score, ml_score = self.ml.predict(features)
            correlation_score, category_severity = self.correlation.score(z_scores)
            risk_score, level = self.risk.assess(ml_score, statistical_score, correlation_score)
            print(f"[RISK] risk_score = {risk_score:.6f}; risk_level = {level}")
            model_anomaly = prediction == "ANOMALY"
            combined_anomaly = level != "NORMAL"
            result = {"host": normalized["host"], "window_seconds": self.config["window_seconds"],
                "features": features, "scores": {"ml": round(ml_score, 6), "statistical": round(statistical_score, 6),
                    "correlation": round(correlation_score, 6), "risk": round(risk_score, 6)},
                "category_severity": {key: round(value, 6) for key, value in category_severity.items()},
                "level": level, "interpretation": "Behavioral deviation is not proof of an attack.",
                "event_count": len(window_events), "status": "ANOMALY" if model_anomaly or combined_anomaly else "NORMAL",
                "reason": "ML_BEHAVIORAL_DEVIATION" if model_anomaly else
                    ("COMBINED_RISK_THRESHOLD" if combined_anomaly else "NO_ANOMALY_DETECTED"),
                "prediction": prediction, "anomaly_score": anomaly_score, "risk_score": risk_score}
            if result["status"] == "ANOMALY":
                result["action"] = "ALERT"
            if result["status"] == "NORMAL":
                self.baseline.update(features)
            elif level != "NORMAL":
                self._preserve_evidence(normalized, window_events, result)
            return result

    def _preserve_evidence(self, event, window_events, result):
        try:
            if self.evidence_store is None:
                self.evidence_store = MinioEvidenceStore(self.config["evidence"])
            safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", event["host"])[:128] or "unknown"
            key = f"{safe_host}/{event['timestamp'].replace(':', '-')}-{uuid.uuid4().hex}.json"
            evidence = {"event": event, "window_events": window_events, "detection": result}
            reference, digest = self.evidence_store.store(key, evidence)
            ledger_entry = self.ledger.append(reference, digest)
            result["evidence"] = {"reference": reference, "sha256": digest, "ledger_entry_hash": ledger_entry["entry_hash"]}
        except Exception as error:
            result["evidence_error"] = str(error)

    def verify_evidence(self, reference, expected_sha256):
        if not self.ledger.verify():
            return {"valid": False, "reason": "Integrity ledger hash chain verification failed"}
        if not self.ledger.contains(reference, expected_sha256):
            return {"valid": False, "reason": "Evidence reference and SHA-256 are not recorded in the ledger"}
        if self.evidence_store is None:
            self.evidence_store = MinioEvidenceStore(self.config["evidence"])
        try:
            valid = self.evidence_store.verify(reference, expected_sha256)
        except Exception as error:
            return {"valid": False, "reason": str(error)}
        return {"valid": valid, "reason": None if valid else "Evidence SHA-256 mismatch"}
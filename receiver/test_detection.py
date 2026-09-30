import json
import tempfile
import unittest
from pathlib import Path

from detection import CorrelationEngine, DetectionPipeline, FeatureExtractor, IntegrityLedger, RollingWindowAggregator, RiskEngine, StatisticalBaseline, StatisticalDetector, load_config


class DetectionComponentsTests(unittest.TestCase):
    def test_feature_extractor_maps_authentication_and_destination(self):
        delta, categories, destination = FeatureExtractor().extract({
            "source": "authentication", "timestamp": "2026-09-29T12:00:00Z",
            "event": {"message": "Failed SSH login from 203.0.113.8"},
        })
        self.assertEqual(delta["failed_login_count"], 1)
        self.assertIn("authentication", categories)
        self.assertEqual(destination, "203.0.113.8")

    def test_rolling_window_aggregates_and_expires_events(self):
        aggregator = RollingWindowAggregator(60)
        first = {"host": "node-a", "timestamp": "2026-09-29T12:00:00Z"}
        later = {"host": "node-a", "timestamp": "2026-09-29T12:01:01Z"}
        features, _, _ = aggregator.add(first, {"failed_login_count": 1}, {"authentication"}, None)
        self.assertEqual(features["failed_login_count"], 1)
        features, _, events = aggregator.add(later, {"sudo_count": 1}, {"privilege_escalation"}, None)
        self.assertEqual(features["failed_login_count"], 0)
        self.assertEqual(features["sudo_count"], 1)
        self.assertEqual(len(events), 1)

    def test_baseline_and_correlation_score_multiple_categories(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline = StatisticalBaseline(Path(temporary) / "baseline.json", 3)
            ordinary = {feature: 1.0 for feature in (
                "failed_login_count", "successful_login_count", "sudo_count", "process_count",
                "network_connection_count", "unique_destination_ip_count", "file_event_count", "cron_event_count")}
            for _ in range(8):
                baseline.update(ordinary)
            spike = dict(ordinary, failed_login_count=30.0, sudo_count=25.0, process_count=40.0, network_connection_count=50.0)
            statistical_score, z_scores = StatisticalDetector(baseline, 2.5).score(spike)
            correlation_score, _ = CorrelationEngine({"correlation_z_threshold": 2.5,
                "correlation_category_weight": 0.08, "correlation_pair_weight": 0.12,
                "related_pairs": [["authentication", "privilege_escalation"], ["process", "network"]]}).score(z_scores)
            self.assertGreater(statistical_score, 0)
            self.assertGreater(correlation_score, 0)

    def test_correlated_anomalies_score_above_isolated_signal(self):
        engine = CorrelationEngine({"correlation_z_threshold": 2.5,
            "correlation_category_weight": 0.08, "correlation_pair_weight": 0.12,
            "related_pairs": [["authentication", "privilege_escalation"]]})
        isolated, _ = engine.score({"failed_login_count": 20.0})
        correlated, _ = engine.score({"failed_login_count": 20.0, "sudo_count": 20.0})
        self.assertGreater(correlated, isolated)

    def test_risk_thresholds_are_configurable(self):
        engine = RiskEngine({"ml": 0.0, "statistical": 0.0, "correlation": 1.0},
            {"suspicious": 0.4, "critical": 0.8})
        score, level = engine.assess(0, 0, 0.5)
        self.assertEqual(score, 0.5)
        self.assertEqual(level, "SUSPICIOUS")

    def test_integrity_ledger_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.jsonl"
            ledger = IntegrityLedger(path)
            ledger.append("bucket/object.json", "a" * 64)
            self.assertTrue(ledger.verify())
            path.write_text(path.read_text().replace("bucket/object.json", "bucket/edited.json"), encoding="utf-8")
            self.assertFalse(ledger.verify())

    def test_pipeline_preserves_only_risky_results_as_evidence(self):
        class AnomalousModel:
            def decision_function(self, frame):
                return [-1.0]

        class EvidenceStore:
            def __init__(self):
                self.objects = {}

            def store(self, key, payload):
                import hashlib
                import json
                digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                self.objects[key] = (payload, digest)
                return f"ghostware-evidence/{key}", digest

            def verify(self, reference, expected_sha256):
                key = reference.split("/", 1)[1]
                return self.objects[key][1] == expected_sha256

        with tempfile.TemporaryDirectory() as temporary:
            config = load_config()
            config["baseline_path"] = str(Path(temporary) / "baseline.json")
            config["baseline_seed_path"] = str(Path(temporary) / "missing.csv")
            config["model_path"] = str(Path(temporary) / "missing.pkl")
            config["evidence"]["ledger_path"] = str(Path(temporary) / "ledger.jsonl")
            config["risk_weights"] = {"ml": 1.0, "statistical": 0.0, "correlation": 0.0}
            config["thresholds"] = {"suspicious": 0.5, "critical": 0.9}
            store = EvidenceStore()
            pipeline = DetectionPipeline(config=config, model=AnomalousModel(), evidence_store=store)
            result = pipeline.process({"host": "node-a", "timestamp": "2026-09-29T12:00:00Z",
                "features": {"failed_login_count": 1}})
            self.assertIn(result["level"], ("SUSPICIOUS", "CRITICAL"))
            self.assertIn("evidence", result)
            self.assertEqual(len(store.objects), 1)
            preserved = next(iter(store.objects.values()))[0]
            self.assertEqual(preserved["event"]["host"], "node-a")
            self.assertIn(preserved["detection"]["level"], ("SUSPICIOUS", "CRITICAL"))
            self.assertIn("not proof of an attack", result["interpretation"])
            self.assertTrue(pipeline.verify_evidence(result["evidence"]["reference"], result["evidence"]["sha256"])["valid"])


if __name__ == "__main__":
    unittest.main()
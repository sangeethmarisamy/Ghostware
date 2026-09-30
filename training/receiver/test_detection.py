import json
import tempfile
import unittest
from pathlib import Path

try:
    from .detection import DetectionPipeline, FEATURES, load_config, normalize_event
except ImportError:
    from detection import DetectionPipeline, FEATURES, load_config, normalize_event


TRAINING_ROOT = Path(__file__).resolve().parent.parent


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        config = load_config()
        config["baseline_path"] = str(Path(self.temp_dir.name) / "baseline.json")
        config["baseline_seed_path"] = str(TRAINING_ROOT / "data" / "training_data.csv")
        config["model_path"] = str(TRAINING_ROOT / "model" / "anomaly_model.pkl")
        config["evidence"]["ledger_path"] = str(Path(self.temp_dir.name) / "ledger.jsonl")
        self.pipeline = DetectionPipeline(config)
        self.pipeline._preserve_evidence = lambda *args: None

    def event(self, **fields):
        return {"host": "test-host", "timestamp": "2026-09-30T12:00:00+00:00", **fields}

    def test_ip_mismatch_blocks_before_pipeline(self):
        result = self.pipeline.process(self.event(username="sangeeth", local_ip="192.168.1.20",
            remote_ip="10.83.235.209"))
        self.assertEqual(result["reason"], "LOCAL_REMOTE_IP_MISMATCH")
        self.assertEqual(result["action"], "BLOCK_REMOTE_IP")
        self.assertEqual(result["username"], "sangeeth")
        self.assertEqual(result["remote_ip"], "10.83.235.209")

    def test_matching_or_missing_ip_does_not_trigger_ip_rule(self):
        matching = self.pipeline.process(self.event(local_ip="192.168.1.20", remote_ip="192.168.1.20"))
        missing = self.pipeline.process(self.event(local_ip="192.168.1.20"))
        self.assertNotEqual(matching.get("reason"), "LOCAL_REMOTE_IP_MISMATCH")
        self.assertNotEqual(missing.get("reason"), "LOCAL_REMOTE_IP_MISMATCH")

    def test_failed_login_block_is_strictly_over_ten(self):
        base = {"source": "authentication", "event_type": "login_failure",
            "metadata": {"username": "sangeeth"}, "local_ip": "192.168.1.20",
            "remote_ip": "192.168.1.20"}
        tenth = None
        for _ in range(10):
            tenth = self.pipeline.process(self.event(**base))
        self.assertNotEqual(tenth.get("reason"), "EXCESSIVE_FAILED_LOGINS")
        eleventh = self.pipeline.process(self.event(**base))
        self.assertEqual(eleventh["reason"], "EXCESSIVE_FAILED_LOGINS")
        self.assertEqual(eleventh["failed_login_count"], 11)
        self.assertEqual(eleventh["action"], "BLOCK_IP")
        self.assertEqual(eleventh["username"], "sangeeth")

    def test_saved_model_labels_normal_and_anomaly_samples(self):
        samples = (
            ("NORMAL", [1, 5, 2, 80, 30, 5, 50, 2]),
            ("ANOMALY", [0, 1, 50, 500, 900, 100, 800, 30]),
        )
        for expected, values in samples:
            features = dict(zip(FEATURES, values))
            result = self.pipeline.process(self.event(host=f"sample-{expected}", features=features))
            self.assertEqual(result["prediction"], expected)
            self.assertEqual(result["status"], expected)
            self.assertTrue("risk_score" in result)
            if expected == "ANOMALY":
                self.assertEqual(result["reason"], "ML_BEHAVIORAL_DEVIATION")
                self.assertEqual(result["action"], "ALERT")

    def test_collector_event_type_and_metadata_reach_features(self):
        event = self.event(source="authentication", event_type="login_failure",
            metadata={"username": "sangeeth"})
        normalized = self.pipeline.process(event)
        self.assertEqual(event["metadata"]["username"], "sangeeth")
        self.assertEqual(normalized["features"]["failed_login_count"], 1.0)

        file_event = self.event(source="file", event_type="file_modify",
            raw="/home/sangeeth/Projects/ghostware/collector/state/process.cursor")
        delta, _, _ = self.pipeline.extractor.extract(file_event)
        self.assertEqual(delta["file_event_count"], 1.0)
        self.assertEqual(delta["process_count"], 0.0)

    def test_repository_collector_samples_preserve_and_extract(self):
        events = json.loads((TRAINING_ROOT.parent / "test_events.json").read_text(encoding="utf-8"))
        normalized_events = [normalize_event(event) for event in events]
        for event, normalized in zip(events, normalized_events):
            self.assertEqual(normalized["source"], event["source"])
            self.assertEqual(normalized["event_type"], event["event_type"])
            self.assertEqual(normalized["metadata"], event["metadata"])
            self.assertEqual(normalized["host"], event["hostname"])
        extracted = [self.pipeline.extractor.extract(event) for event in normalized_events]
        self.assertEqual(len(extracted), 5)
        auth_event = events[0]
        auth_features = extracted[0][0]
        self.assertEqual(auth_event["metadata"]["username"], "sangeeth")
        self.assertEqual(auth_features["successful_login_count"], 1.0)
        self.assertEqual(auth_features["network_connection_count"], 0.0)
        network_event = events[-1]
        network_features, _, destination_ip = extracted[-1]
        self.assertEqual(network_event["event_type"], "network_packet")
        self.assertEqual(network_features["network_connection_count"], 1.0)
        self.assertEqual(destination_ip, network_event["metadata"]["ipv6_dst"])


if __name__ == "__main__":
    unittest.main()
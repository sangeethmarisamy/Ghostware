# Ghostware Detection Pipeline

The receiver processes each WebSocket JSON event through separate components in `detection.py`:

1. `normalize_event` validates the top-level object and normalizes host and timestamp.
2. `FeatureExtractor` maps collector messages or explicit `features` into eight security features.
3. `RollingWindowAggregator` builds per-host feature counts over the configured time window.
4. `StatisticalBaseline` maintains persisted online mean/variance statistics, seeded from the local Ghostware training CSV when no baseline exists. Only NORMAL windows update the baseline.
5. `IsolationForestDetector` scores feature combinations using the model trained by `training/train.py`.
6. `CorrelationEngine` raises the correlation contribution when anomalous categories form configured related pairs.
7. `RiskEngine` combines configured weights and emits NORMAL, SUSPICIOUS, or CRITICAL. An anomaly is a behavioral deviation, not proof of an attack.
8. Only SUSPICIOUS and CRITICAL results are sent to MinIO evidence storage. The evidence SHA-256, object reference, and predecessor hash are recorded in a local append-only integrity chain.

## Run

Install the root `requirements.txt`, then start the receiver from the repository root:

```powershell
python -m receiver.server
```

The Linux collector scripts use `collector/transport.py` to publish event objects to `GHOSTWARE_WS_URL` (default `ws://127.0.0.1:8765`). Set MinIO connection settings before starting the receiver:

```text
GHOSTWARE_MINIO_ENDPOINT=minio.example:9000
GHOSTWARE_MINIO_ACCESS_KEY=...
GHOSTWARE_MINIO_SECRET_KEY=...
```

Use `receiver/detection_config.json` to tune the rolling window, minimum baseline samples, Z-score gates, related category pairs, risk weights, and classification thresholds. MinIO is required to preserve evidence; without it, the response includes `evidence_error` and no success is claimed.

To verify evidence, send a WebSocket JSON request with `action` set to `verify_evidence` and provide the returned `reference` and `sha256`. Verification checks both the ledger chain and the MinIO object's current bytes.

The integrity chain is local and detects edits or broken predecessor links. It does not provide distributed consensus or protection against an administrator who can rewrite the ledger and all subsequent hashes; connect an external blockchain or immutable ledger service if those guarantees are required.
# Hybrid AI-Powered Intrusion Detection System

A scaffold for a hybrid NIDS/HIDS: signature-based rules for known attack
patterns, plus an Isolation Forest anomaly detector over network flow
features, unified into a single alert pipeline.

## Architecture

```
                ┌────────────────┐        per-packet        ┌──────────────────┐
   NIC  ─────►  │ PacketCapture  │ ───────────────────────► │ SignatureEngine   │
 (scapy)        │ (core/capture) │                          │ .on_packet()      │──┐
                └───────┬────────┘                          │ (rate/window      │  │
                        │ flow expiry                       │  rules: port scan,│  │
                        ▼                                   │  SYN/ICMP flood,  │  │
                ┌────────────────┐                           │  blacklist ports) │  │
                │  AnomalyEngine │                           └──────────────────┘  │
                │ (Isolation     │                                                  │
                │  Forest)       │──────────────────────────────────────────────────┤
                └────────────────┘                                                  │
                                                                                      ▼
 Host logs ───► LogTailer ──► SignatureEngine.on_log_line()  ──────────────►  AlertManager
(auth.log)     (core/log_       (brute force, login-after-                   (dedup, log,
                monitor)         burst correlation, etc.)                     console/file)
```

- **core/flow.py** — `Flow` / `FlowTable`: aggregates packets into bidirectional
  5-tuple flows and exposes a numeric feature vector for ML scoring.
- **core/capture.py** — live packet sniffing (scapy), feeds both the
  signature engine (per-packet) and the flow table (for ML, on flow expiry).
- **core/log_monitor.py** — polls host log files for new lines (SSH auth, etc).
- **detection/signature_engine.py** — data-driven rule engine; rules live in
  `rules/rules.yaml`, not in code. Handles sliding-window rate rules
  (port scans, floods) and host log pattern/correlation rules.
- **detection/ml_engine.py** — loads a trained Isolation Forest + scaler,
  scores completed flows, flags ones below `ml_score_threshold`.
- **alerts/alert_manager.py** — single sink for all alerts; dedups repeats,
  writes JSON lines to `alerts.log`, prints to console.
- **main.py** — wires everything together and runs the event loop.
- **train_model.py** — offline trainer; takes a CSV of normal-traffic flow
  features and produces `models/anomaly_model.joblib` + `scaler.joblib`.

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Packet capture needs raw socket access:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python3)
# or simply run main.py with sudo
```

## Quick start (synthetic data, to verify the pipeline)

```bash
python data/generate_synthetic_normal.py --out data/normal_flows.csv --rows 5000
python train_model.py --csv data/normal_flows.csv
sudo python main.py
```

Then, in another terminal, generate some traffic to see signature rules fire,
e.g. a basic port scan with `nmap -p 1-100 <target>` against a host you're
authorized to test, or simulate failed SSH logins against a test box.

## Replacing synthetic data with real training data

The synthetic generator only exists to prove the pipeline runs end-to-end —
its statistical assumptions are fake and won't reflect your real network.
Before relying on this for actual detection:

1. Capture real benign traffic on your network for a representative period
   (varied times of day, normal application mix), confirm it contains no
   attacks, and export flow features in the same CSV schema (see
   `detection/ml_engine.py:FEATURE_NAMES`).
2. Or use a labeled public dataset (e.g. CICIDS2017/2018, UNSW-NB15) and
   filter to benign rows, remapping their fields to this schema.
3. Re-run `train_model.py` on that data, then check the printed score
   distribution and tune `ml_score_threshold` in `config.yaml` —
   start near the 1st–5th percentile of training scores and adjust based
   on false-positive rate during a monitoring-only burn-in period.

## Tuning rules

Edit `rules/rules.yaml` directly — thresholds, windows, and ports are data,
no code changes needed for new instances of existing rule types
(`port_scan`, `syn_flood`, `icmp_flood`, `blacklisted_port`,
`failed_login_burst`, `login_after_burst`, `pattern_match`). Adding a new
rule *type* means adding a handler in `detection/signature_engine.py`.

## Known limitations of this scaffold (next steps)

- Single-process, in-memory state — won't survive restarts or scale across
  multiple sensors. For production, persist flow/alert state externally
  (Redis) and consider a message bus (Kafka) between capture and detection.
- IPv6 not handled in `capture.py` (`IP` is IPv4-only in scapy by default;
  add an `IPv6` branch if needed).
- No automatic model retraining/drift detection — anomaly thresholds will
  go stale as your network's baseline traffic changes.
- No authentication/encryption on alert outputs — if you forward alerts to
  a webhook/SIEM, secure that channel yourself.
- This tool is for monitoring traffic/logs you are authorized to observe
  (your own network/hosts or with explicit permission). Don't point it at
  networks you don't own or have permission to monitor.

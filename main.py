import os
import sys

# Auto-reexec with local virtual environment Python if dependencies missing
try:
    import scapy
except ImportError:
    venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin", "python")
    if os.path.exists(venv_python) and os.path.abspath(sys.executable) != os.path.abspath(venv_python):
        os.execv(venv_python, [venv_python] + sys.argv)

import logging
import signal
import time
import threading

import yaml


from core.flow import FlowTable
from core.capture import PacketCapture
from core.log_monitor import LogTailer
from detection.signature_engine import SignatureEngine
from detection.ml_engine import AnomalyEngine
from alerts.alert_manager import AlertManager
from web_server import app, application, handler, run_web_server, set_flow_table


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s: %(message)s",
)
log = logging.getLogger("ids.main")


def load_config(path="config.yaml"):
    """Load configuration options from a YAML file."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    cfg = load_config()

    alert_mgr = AlertManager(
        log_file=cfg["alerts"]["log_file"],
        console=cfg["alerts"]["console"],
        dedup_window_sec=cfg["alerts"]["dedup_window_sec"],
    )

    sig_engine = SignatureEngine(
        rules_path=cfg["detection"]["signature_rules_path"],
        alert_callback=alert_mgr.emit,
    )

    ml_engine = AnomalyEngine(
        model_path=cfg["detection"]["ml_model_path"],
        scaler_path=cfg["detection"]["ml_scaler_path"],
        score_threshold=cfg["detection"]["ml_score_threshold"],
        min_packets=cfg["detection"]["ml_min_packets_for_eval"],
    )
    if not ml_engine.ready():
        log.warning("Running WITHOUT ML anomaly detection (no trained model). "
                     "Signature detection still active. See train_model.py.")

    flow_table = FlowTable()
    set_flow_table(flow_table)

    def on_expired_flow(flow):
        is_anom, score = ml_engine.score_flow(flow)
        if is_anom:
            summary = (f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                       f"({flow.proto}, {flow.packet_count} pkts, {flow.byte_count} bytes)")
            alert_mgr.ml_alert(
                source=flow.src_ip, score=score,
                threshold=cfg["detection"]["ml_score_threshold"],
                flow_summary=summary,
            )

    capture = PacketCapture(
        interface=cfg["network"]["interface"],
        bpf_filter=cfg["network"]["bpf_filter"],
        flow_table=flow_table,
        flush_interval_sec=cfg["network"]["flow_flush_interval_sec"],
        flow_timeout_sec=cfg["network"]["flow_timeout_sec"],
        on_flow_update=sig_engine.on_packet,
    )
    capture.start(on_expired_flow=on_expired_flow)
    log.info("Network capture + signature engine started.")

    log_tailer = None
    if cfg["host"]["enabled"]:
        log_tailer = LogTailer(
            paths=cfg["host"]["log_paths"],
            poll_interval_sec=cfg["host"]["poll_interval_sec"],
            on_line=sig_engine.on_log_line,
        )
        log_tailer.start()
        log.info("Host log monitor started.")

    # Start Web Dashboard Server (if enabled)
    if cfg.get("web", {}).get("enabled", True):
        web_host = cfg["web"].get("host", "0.0.0.0")
        web_port = cfg["web"].get("port", 5000)
        web_thread = threading.Thread(
            target=run_web_server,
            kwargs={"host": web_host, "port": web_port},
            daemon=True,
        )
        web_thread.start()
        log.info("Web Dashboard UI running at http://%s:%d", web_host, web_port)

    def shutdown(*_):
        log.info("Shutting down...")
        capture.stop()
        if log_tailer:
            log_tailer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log.info("IDS running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()


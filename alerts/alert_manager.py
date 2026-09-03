import time
import json
import logging
import threading

log = logging.getLogger("ids.alerts")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class AlertManager:
    def __init__(self, log_file, console, dedup_window_sec):
        self.log_file = log_file
        self.console = console
        self.dedup_window_sec = dedup_window_sec
        self._lock = threading.Lock()
        self._last_seen = {}

    def emit(self, rule_id, name, severity, message, source="unknown"):
        now = time.time()
        dedup_key = (rule_id, source)
        with self._lock:
            last = self._last_seen.get(dedup_key)
            if last and (now - last) < self.dedup_window_sec:
                return
            self._last_seen[dedup_key] = now

        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "rule_id": rule_id,
            "name": name,
            "severity": severity,
            "source": source,
            "message": message,
        }
        line = json.dumps(record)

        if self.console:
            tag = severity.upper()
            print(f"[{record['timestamp']}] [{tag}] {name} ({rule_id}) — {message}")

        try:
            with open(self.log_file, "a") as f:
                f.write(line + "\n")
        except OSError:
            log.exception("Failed writing alert to %s", self.log_file)

    def ml_alert(self, source, score, threshold, flow_summary):
        self.emit(
            rule_id="ML-ANOMALY",
            name="Anomalous traffic flow (ML)",
            severity="medium",
            message=f"Isolation Forest score={score:.3f} (threshold={threshold:.3f}) — {flow_summary}",
            source=source,
        )

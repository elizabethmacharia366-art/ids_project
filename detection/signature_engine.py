import re
import time
import logging
import yaml
from collections import defaultdict, deque

log = logging.getLogger("ids.signature")


class SignatureEngine:
    def __init__(self, rules_path, alert_callback):
        self.alert = alert_callback
        with open(rules_path, "r") as f:
            rules = yaml.safe_load(f)
        self.network_rules = rules.get("network_rules", [])
        self.host_rules = rules.get("host_rules", [])

        self._port_touches = defaultdict(lambda: deque())
        self._syn_counts = defaultdict(lambda: deque())
        self._icmp_counts = defaultdict(lambda: deque())
        self._failed_logins = defaultdict(lambda: deque())
        self._recent_bursts = {}

        self._compiled_host_rules = []
        for rule in self.host_rules:
            entry = dict(rule)
            entry["_pattern_re"] = re.compile(rule["pattern"], re.IGNORECASE)
            if "ip_regex" in rule:
                entry["_ip_re"] = re.compile(rule["ip_regex"])
            self._compiled_host_rules.append(entry)

        blacklist_rule = next((r for r in self.network_rules if r["type"] == "blacklisted_port"), None)
        self._blacklisted_ports = set(blacklist_rule["ports"]) if blacklist_rule else set()

    def on_packet(self, flow, src_ip, dst_ip, proto, flags):
        now = time.time()

        for rule in self.network_rules:
            rtype = rule["type"]

            if rtype == "port_scan" and proto in ("TCP", "UDP"):
                self._check_port_scan(rule, src_ip, dst_ip, now)

            elif rtype == "syn_flood" and proto == "TCP" and "S" in flags and "A" not in flags:
                self._check_rate_rule(
                    rule, self._syn_counts, src_ip, now,
                    threshold_key="syn_count_threshold",
                    label=f"SYN flood from {src_ip}",
                )

            elif rtype == "icmp_flood" and proto == "ICMP":
                self._check_rate_rule(
                    rule, self._icmp_counts, src_ip, now,
                    threshold_key="icmp_count_threshold",
                    label=f"ICMP flood from {src_ip}",
                )

            elif rtype == "blacklisted_port" and flow.dst_port in self._blacklisted_ports:
                self.alert(
                    rule_id=rule["id"], name=rule["name"], severity=rule["severity"],
                    message=f"{src_ip} -> {dst_ip}:{flow.dst_port} ({proto}) matches blacklisted port",
                    source=src_ip,
                )

    def _check_port_scan(self, rule, src_ip, dst_ip, now):
        window = rule["window_sec"]
        dq = self._port_touches[src_ip]
        dq.append((now, dst_ip))
        while dq and now - dq[0][0] > window:
            dq.popleft()
        unique_targets = len({d for _, d in dq})
        if unique_targets >= rule["unique_ports_threshold"]:
            self.alert(
                rule_id=rule["id"], name=rule["name"], severity=rule["severity"],
                message=f"{src_ip} touched {unique_targets} distinct destinations in {window}s",
                source=src_ip,
            )
            dq.clear()

    def _check_rate_rule(self, rule, state_dict, src_ip, now, threshold_key, label):
        window = rule["window_sec"]
        dq = state_dict[src_ip]
        dq.append(now)
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= rule[threshold_key]:
            self.alert(
                rule_id=rule["id"], name=rule["name"], severity=rule["severity"],
                message=f"{label}: {len(dq)} events in {window}s",
                source=src_ip,
            )
            dq.clear()

    def on_log_line(self, path, line):
        now = time.time()
        for rule in self._compiled_host_rules:
            if not rule["_pattern_re"].search(line):
                continue

            ip_match = rule["_ip_re"].search(line) if "_ip_re" in rule else None
            source = ip_match.group(1) if ip_match else path

            if rule["type"] == "failed_login_burst":
                self._check_failed_login_burst(rule, source, now)
            elif rule["type"] == "login_after_burst":
                self._check_login_after_burst(rule, source, now)
            elif rule["type"] == "pattern_match":
                self.alert(
                    rule_id=rule["id"], name=rule["name"], severity=rule["severity"],
                    message=f"Pattern match in {path}: {line.strip()[:200]}",
                    source=source,
                )

    def _check_failed_login_burst(self, rule, src_ip, now):
        window = rule["window_sec"]
        dq = self._failed_logins[src_ip]
        dq.append(now)
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= rule["count_threshold"]:
            self.alert(
                rule_id=rule["id"], name=rule["name"], severity=rule["severity"],
                message=f"{len(dq)} failed logins from {src_ip} in {window}s",
                source=src_ip,
            )
            self._recent_bursts[src_ip] = now
            dq.clear()

    def _check_login_after_burst(self, rule, src_ip, now):
        burst_time = self._recent_bursts.get(src_ip)
        if burst_time and (now - burst_time) <= rule["correlate_window_sec"]:
            self.alert(
                rule_id=rule["id"], name=rule["name"], severity=rule["severity"],
                message=f"Successful login from {src_ip} shortly after a failed-login burst "
                        f"({now - burst_time:.0f}s later) — possible compromised credentials",
                source=src_ip,
            )
            del self._recent_bursts[src_ip]

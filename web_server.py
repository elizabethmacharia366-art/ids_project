"""Web Server & REST API Backend for the IDS Security Dashboard."""

import os
import json
import random
import time
import logging
from flask import Flask, render_template, jsonify, request

log = logging.getLogger("ids.web")

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "web", "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "web", "static"),
)

LOG_FILE = "alerts.log"
FLOW_TABLE_REF = None


def set_flow_table(flow_table):
    """Register flow table reference for live flow metrics API."""
    global FLOW_TABLE_REF
    FLOW_TABLE_REF = flow_table


def read_alerts_from_log():
    """Read and parse alert records from the alerts.log file."""
    alerts = []
    if not os.path.exists(LOG_FILE):
        return alerts

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    alerts.append(record)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        log.error("Failed reading alert log: %s", e)

    return alerts


@app.route("/")
def index():
    """Render the primary IDS Dashboard UI."""
    return render_template("index.html")


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Return filtered alert records."""
    alerts = read_alerts_from_log()
    
    # Filter parameters
    severity = request.args.get("severity", "all").lower()
    search = request.args.get("search", "").lower()
    limit = request.args.get("limit", type=int, default=100)

    if severity != "all":
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity]

    if search:
        alerts = [
            a for a in alerts
            if search in a.get("source", "").lower()
            or search in a.get("name", "").lower()
            or search in a.get("rule_id", "").lower()
            or search in a.get("message", "").lower()
        ]

    # Sort newest first
    alerts.reverse()

    return jsonify({
        "status": "success",
        "total": len(alerts),
        "alerts": alerts[:limit],
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return aggregate alert statistics for dashboard cards and charts."""
    alerts = read_alerts_from_log()

    total_alerts = len(alerts)
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sources = {}
    sig_count = 0
    ml_count = 0

    for a in alerts:
        sev = a.get("severity", "low").lower()
        if sev in severities:
            severities[sev] += 1
        
        src = a.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1

        rule_id = a.get("rule_id", "")
        if "ML" in rule_id or "ANOMALY" in rule_id:
            ml_count += 1
        else:
            sig_count += 1

    top_sources = sorted(
        [{"ip": ip, "count": count} for ip, count in sources.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    active_flows_count = 0
    if FLOW_TABLE_REF:
        try:
            active_flows_count = len(FLOW_TABLE_REF.snapshot())
        except Exception:
            pass

    return jsonify({
        "status": "success",
        "total_alerts": total_alerts,
        "severities": severities,
        "unique_sources": len(sources),
        "top_sources": top_sources,
        "signature_alerts": sig_count,
        "ml_alerts": ml_count,
        "active_flows": active_flows_count,
    })


@app.route("/api/flows", methods=["GET"])
def get_flows():
    """Return active flow table snapshots."""
    flows_data = []
    if FLOW_TABLE_REF:
        try:
            snapshot = FLOW_TABLE_REF.snapshot()
            for f in snapshot[:50]:
                flows_data.append({
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "proto": f.proto,
                    "packet_count": f.packet_count,
                    "byte_count": f.byte_count,
                    "duration": round(f.duration(), 2),
                })
        except Exception as e:
            log.error("Error retrieving flow snapshot: %s", e)

    return jsonify({
        "status": "success",
        "total_flows": len(flows_data),
        "flows": flows_data,
    })


@app.route("/api/alerts/simulate", methods=["POST"])
def simulate_alert():
    """Inject a test alert into alerts.log for demonstration."""
    sample_rules = [
        {
            "rule_id": "NET-001",
            "name": "Port scan detected",
            "severity": "high",
            "message": "Source touched 24 distinct destination ports in 10s",
        },
        {
            "rule_id": "NET-002",
            "name": "SYN flood suspected",
            "severity": "critical",
            "message": "SYN flood from 192.168.1.105: 142 events in 5s",
        },
        {
            "rule_id": "HOST-001",
            "name": "Repeated failed SSH logins",
            "severity": "high",
            "message": "8 failed logins from 10.0.0.45 in 60s",
        },
        {
            "rule_id": "ML-ANOMALY",
            "name": "Anomalous traffic flow (ML)",
            "severity": "medium",
            "message": "Isolation Forest score=-0.218 (threshold=-0.150) — 192.168.1.50:443 -> 10.0.0.12:51234",
        },
    ]

    selected = random.choice(sample_rules)
    fake_ip = f"192.168.{random.randint(1, 10)}.{random.randint(2, 254)}"

    record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "rule_id": selected["rule_id"],
        "name": selected["name"],
        "severity": selected["severity"],
        "source": fake_ip,
        "message": selected["message"].replace("192.168.1.105", fake_ip),
    }

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "success", "alert": record})


@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    """Clear all records from alerts.log."""
    try:
        open(LOG_FILE, "w").close()
        return jsonify({"status": "success", "message": "Alert log cleared"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def run_web_server(host="0.0.0.0", port=5000):
    """Start the Flask web server."""
    # Suppress verbose default werkzeug logging in production/background mode
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_web_server()

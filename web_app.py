from flask import Flask, render_template, request, send_file
import os
import io

from core.log_reader import LogReader
from core.log_parser import LogParser
from core.analyzer import Analyzer
from core.risk_engine import RiskEngine
from core.alert_manager import AlertManager
from core.report_generator import ReportGenerator
from core.geolocation import get_country

app = Flask(__name__)

UPLOAD_FOLDER = "logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

latest_report = {}
latest_ip_counts = {}

# ---------- PROCESS ----------
def process_events(events):
    analyzer = Analyzer(events)
    suspicious_ips = analyzer.detect_failed_logins()

    ip_counts = {}
    for ip, attempts in suspicious_ips:
        ip_counts[ip] = {
            "count": attempts,
            "country": get_country(ip)
        }

    risk_engine = RiskEngine()
    alerts_data = risk_engine.calculate_risk(suspicious_ips)

    alert_manager = AlertManager()
    alerts = alert_manager.generate_alerts(alerts_data)

    report_generator = ReportGenerator()
    report_data = report_generator.generate_report(events, alerts_data)

    report = {
        "total_events": report_data["total_events"],
        "suspicious_ips": report_data["suspicious_ips"],
        "severity": report_data["severity_summary"]
    }

    return alerts, report, ip_counts

# ---------- HOME ----------
@app.route("/", methods=["GET", "POST"])
def index():
    alerts = []
    report = None
    ip_counts = {}

    if request.method == "POST":
        file = request.files.get("logfile")

        if file and file.filename != "":
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)

            reader = LogReader(filepath)
            parser = LogParser()

            events = []
            for line in reader.read_logs():
                event = parser.parse(line)
                if event and event.event_type != "UNKNOWN":
                    events.append(event)

            alerts, report, ip_counts = process_events(events)

            global latest_report, latest_ip_counts
            latest_report = report
            latest_ip_counts = ip_counts

    return render_template("index.html",
                           alerts=alerts,
                           report=report,
                           ip_counts=ip_counts,
                           mode="upload")

# ---------- LIVE ----------
@app.route("/live")
def live():
    parser = LogParser()
    events = []

    with open("/var/log/auth.log", "r") as f:
        lines = f.readlines()[-500:]

        for line in lines:
            event = parser.parse(line)
            if event and event.event_type != "UNKNOWN":
                events.append(event)

    alerts, report, ip_counts = process_events(events)

    global latest_report, latest_ip_counts
    latest_report = report
    latest_ip_counts = ip_counts

    return render_template("index.html",
                           alerts=alerts,
                           report=report,
                           ip_counts=ip_counts,
                           mode="live")

# ---------- DOWNLOAD ----------
@app.route("/download_report")
def download_report():
    global latest_report, latest_ip_counts

    if not latest_report:
        return "No report generated yet"

    content = "Mini SIEM Security Report\n\n"
    content += f"Total Events: {latest_report['total_events']}\n"
    content += f"Suspicious IPs: {latest_report['suspicious_ips']}\n\n"

    content += "Severity Summary:\n"
    for level, count in latest_report["severity"].items():
        content += f"{level}: {count}\n"

    content += "\nAttackers:\n"
    for ip, data in latest_ip_counts.items():
        content += f"{ip} ({data['country']}) -> {data['count']}\n"

    buffer = io.BytesIO()
    buffer.write(content.encode())
    buffer.seek(0)

    return send_file(buffer,
                     as_attachment=True,
                     download_name="siem_report.txt",
                     mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

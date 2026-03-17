from flask import Flask, render_template, request
import os

from core.log_reader import LogReader
from core.log_parser import LogParser
from core.analyzer import Analyzer
from core.risk_engine import RiskEngine
from core.alert_manager import AlertManager
from core.report_generator import ReportGenerator

app = Flask(__name__)
latest_report = {}
latest_ip_counts = {}

UPLOAD_FOLDER = "logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/", methods=["GET", "POST"])
def index():

    alerts = []
    report = None
    ip_counts = {}

    if request.method == "POST":

        file = request.files["logfile"]

        if file and file.filename != "":
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)

            reader = LogReader(filepath)
            parser = LogParser()

            events = []

            for line in reader.read_logs():
                event = parser.parse(line)
                if event:
                    events.append(event)

            analyzer = Analyzer(events)
            suspicious_ips = analyzer.detect_failed_logins()

            for ip, attempts in suspicious_ips:
                ip_counts[ip] = attempts

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
            global latest_report, latest_ip_counts

            latest_report = report
            latest_ip_counts = ip_counts

    return render_template(
        "index.html",
        alerts=alerts,
        report=report,
        ip_counts=ip_counts
    )
from flask import send_file
import io

@app.route("/download_report")
def download_report():

    global latest_report, latest_ip_counts

    content = "Mini SIEM Security Report\n"
    content += "---------------------------\n\n"

    content += f"Total Events: {latest_report.get('total_events',0)}\n"
    content += f"Suspicious IPs: {latest_report.get('suspicious_ips',0)}\n\n"

    content += "Attackers\n"

    for ip, attempts in latest_ip_counts.items():
        content += f"{ip} -> {attempts} attempts\n"

    buffer = io.BytesIO()
    buffer.write(content.encode())
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="siem_report.txt",
        mimetype="text/plain"
    )

if __name__ == "__main__":
    app.run(debug=True)
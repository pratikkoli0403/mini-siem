from realtime import stream_logs
from core.log_parser import LogParser
from core.analyzer import Analyzer
from core.risk_engine import RiskEngine
from core.alert_manager import AlertManager
from core.report_generator import ReportGenerator
from core.geolocation import get_country

parser = LogParser()
events = []

def handle_log(line):
    global events

    event = parser.parse(line)

    if event.event_type != "UNKNOWN":
        events.append(event)

        # 🌍 Add geolocation
        country = get_country(event.source_ip)

        print(f"[{event.event_type}] {event.source_ip} ({country})")

        # Run pipeline every 5 events (lightweight real-time)
        if len(events) % 5 == 0:
            analyzer = Analyzer(events)
            suspicious_ips = analyzer.detect_failed_logins()

            risk_engine = RiskEngine()
            risk_report = risk_engine.calculate_risk(suspicious_ips)

            alert_manager = AlertManager()
            alerts = alert_manager.generate_alerts(risk_report)

            print("\n🚨 Alerts:")
            for alert in alerts:
                print(alert)

if __name__ == "__main__":
    print("[+] Real-Time SIEM Started...\n")
    stream_logs(handle_log)

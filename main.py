from core.log_reader import LogReader
from core.log_parser import LogParser
from core.analyzer import Analyzer
from core.risk_engine import RiskEngine
from core.alert_manager import AlertManager

reader = LogReader("logs/sample_auth.log")
parser = LogParser()

logs = reader.read_logs()
events =[parser.parse(log) for log in logs]

analyzer = Analyzer(events)
suspicious_ips = analyzer.detect_failed_logins()

risk_engine = RiskEngine()
risk_report = risk_engine.calculate_risk(suspicious_ips)

alert_manager = AlertManager()
alerts = alert_manager.generate_alerts(risk_report)

print("Security Alerts:")
for alert in alerts:
    print(alert)
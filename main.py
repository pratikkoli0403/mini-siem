from core.log_reader import LogReader
from core.log_parser import LogParser
from core.analyzer import Analyzer

reader = LogReader("logs/sample_auth.log")
parser = LogParser()

logs = reader.read_logs()
events =[parser.parse(log) for log in logs]

analyzer = Analyzer(events)
results = analyzer.detect_failed_logins()

print("Supicious IPs:")
for ip, count in results:
    print(f"{ip} -> {count} failed attempts")
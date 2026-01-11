from core.log_reader import LogReader
from core.log_parser import LogParser

reader = LogReader("logs/sample_auth.log")
parser = LogParser()

logs = reader.read_logs()

events = []
for log in logs:
    event = parser.parse(log)
    events.append(event)

for event in events:
    print(event)
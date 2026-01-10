from core.log_reader import LogReader

reader = LogReader("logs/sample_auth.log")
logs = reader.read_logs()

for log in logs:
    print(log)

import re
from datetime import datetime
from core.event import Event

failed_attempts = {}

class LogParser:
    def parse(self, log_line):
        event_type = "UNKNOWN"
        source_ip = "UNKNOWN"

        # ---------- IP EXTRACTION (handles both formats) ----------
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log_line)

        if not ip_match:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log_line)

        if ip_match:
            source_ip = ip_match.group(1)

        # ---------- FAILED LOGIN DETECTION ----------
        if ("Failed password" in log_line or 
    	    "Connection closed by authenticating user" in log_line or 
            "Invalid user" in log_line):
            event_type = "FAILED_LOGIN"

            if source_ip != "UNKNOWN":
                failed_attempts[source_ip] = failed_attempts.get(source_ip, 0) + 1

                if failed_attempts[source_ip] >= 5:
                    event_type = "BRUTE_FORCE"

        # ---------- SUCCESS LOGIN ----------
        elif "Accepted password" in log_line:
            event_type = "SUCCESS_LOGIN"

        # ---------- TIMESTAMP ----------
        timestamp_str = log_line[:15]
        try:
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        except:
            timestamp = datetime.now()

        return Event(timestamp, source_ip, event_type, log_line)

import re 
from datetime import datetime
from core.event import Event

class LogParser:
    def parse(self, log_line):
        #default value
        event_type ="UNKNOWN"
        source_ip = "UNKNOWN"


        # Detect failed login
        if "Failed password" in log_line:
            event_type = "FAILED_LOGIN"
        
        #detect successful login
        elif "Accepted password" in log_line:
            event_type = "SUCCESS_LOGIN"
            
        # Extract source IP address using regex
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log_line)
        if ip_match:
            source_ip = ip_match.group(1)
        
        # Timestamp (simplified for now)
        timestamp = log_line[:15]

        return Event(timestamp, source_ip, event_type, log_line)
    
        
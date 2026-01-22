from collections import defaultdict

class Analyzer:
    def __init__(self,events):
        self.events = events
    
    def detect_failed_logins(self, threshold=3):
        failed_attempts = defaultdict(int)
        suspicious_ips = []

        for event in self.events:
            if event.event_type == "FAILED_LOGIN":
                failed_attempts[event.source_ip] +=1
        
        for ip, count in failed_attempts.items():
            if count >= threshold:
                suspicious_ips.append((ip, count))
        
        return suspicious_ips
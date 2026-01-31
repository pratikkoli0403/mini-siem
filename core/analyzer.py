from collections import defaultdict
from datetime import timedelta
from config.setting import FAILED_LOGIN_THRESHOLD, TIME_WINDOW_SECONDS

class Analyzer:
    def __init__(self,events):
        self.events = events
    
    def detect_failed_logins(self, threshold= FAILED_LOGIN_THRESHOLD, window_seconds= TIME_WINDOW_SECONDS):
        ip_failures = defaultdict(list)
        suspicious_ips = []

        for event in self.events:
            if event.event_type == "FAILED_LOGIN":
                ip_failures[event.source_ip].append(event.timestamp)
        
        for ip, times in ip_failures.items():
            times.sort()

            start = 0
            for end in range(len(times)):
                while times[end] - times[start] > timedelta(seconds=window_seconds):
                    start += 1
                
                if (end - start + 1) >= threshold:
                    suspicious_ips.append((ip, end - start + 1))
                    break #one alert per IP is enough
        
        return suspicious_ips
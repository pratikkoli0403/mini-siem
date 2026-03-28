class Analyzer:
    def __init__(self, events):
        self.events = events

    def detect_failed_logins(self):
        ip_count = {}

        for event in self.events:
            if event.event_type in ["FAILED_LOGIN", "BRUTE_FORCE"]:
                ip = event.source_ip

                if ip != "UNKNOWN":
                    ip_count[ip] = ip_count.get(ip, 0) + 1

        # 🔥 LOWER threshold (important for live)
        suspicious = []
        for ip, count in ip_count.items():
            if count >= 2:   # changed from 5 → 2
                suspicious.append((ip, count))

        return suspicious

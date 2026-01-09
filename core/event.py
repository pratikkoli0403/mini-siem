from datetime import datetime

class Event:
    def __init__(self, timestamp, source_ip, event_type, message):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.message = message

    def __str__(self):
            return f"[{self.timestamp}] {self.event_type} from {self.source_ip}"

class AlertManager:
    def generate_alerts(self, risk_report):
        alerts = []

        for item in risk_report:
            ip = item["ip"]
            attempts = item["failed_attempts"]
            severity = item["severity"]

            if severity == "HIGH":
                message = f"[CRITICAL] Possible brute-force attack from {ip} ({attempts} failed attempts)"
            elif severity == "MEDIUM":
                message = f"[WARNING] Suspicious login activity from {ip} ({attempts} failed attempts)"
            else:
                message = f"[INFO] Multiple failed login from {ip} ({attempts} attempts)"

            alerts.append(message)
        
        return alerts

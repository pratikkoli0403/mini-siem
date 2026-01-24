class RiskEngine:
    def calculate_risk(self, suspicious_ips):
        risk_report =[]

        for ip, count in suspicious_ips:
            if count >= 8:
                severity = "high"
            elif count >= 5:
                severity = "medium"
            else:
                severity = "low"

            risk_report.append({
                "ip": ip,
                "failed_attempts": count,
                "severity": severity
            })
        
        return risk_report


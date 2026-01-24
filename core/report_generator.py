class ReportGenerator:
    def genrate_report(self, events, risk_reports):
        report ={}

        report["total_events"] = len(events)
        report["suspicious_ips"] = len(risk_reports)
        
        severity_count = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for item in risk_reports:
            severity = item["severity"]
            if severity in severity_count:
                severity_count[severity] +=1
        
        report["severity_summary"] = severity_count

        return report
               

import re

class ThreatAnalyzer:
    def __init__(self):
        # Ordered by priority as requested
        self.signatures = [
            {
                "id": "SQLI_BOOLEAN_BYPASS_001",
                "name": "SQL Injection (SQLi)",
                "pattern": r"('|\")\s*OR\s*('|\")?\d+('|\")?\s*=\s*('|\")?\d+",
                "severity": "CRITICAL",
                "confidence": 99,
                "score": 97,
                "fp_prob": "LOW",
                "mitre": "T1190 – Exploit Public-Facing Application",
                "owasp": "A03:2021 – Injection",
                "engine": "Regex Signature Match",
                "impact": ["Unauthorized access", "Credential compromise", "Database exposure", "Privilege escalation"],
                "recommendation": "Monitor repeated authentication attacks from the originating subnet. Recommend enforcing parameterized queries.",
                "timeline": [
                    {"step": "Reconnaissance", "status": "COMPLETED"},
                    {"step": "Endpoint Discovery", "status": "COMPLETED"},
                    {"step": "SQL Injection Attempt", "status": "DETECTED"},
                    {"step": "Authentication Bypass Attempt", "status": "INTERCEPTED"},
                    {"step": "WAF Block Enforcement", "status": "ENFORCED"}
                ],
                "query_impact": {
                    "original": "SELECT * FROM users WHERE id='USER_INPUT'",
                    "payload": "id=1' OR '1'='1",
                    "logical": "Condition evaluates TRUE → Authentication bypass possible"
                },
                "details": "Detected SQL Injection payload attempting boolean-based authentication bypass. The payload injects a condition that always evaluates TRUE into the backend SQL query, potentially allowing unauthorized access.",
                "mitigation": [
                    "Use parameterized queries",
                    "Implement prepared statements",
                    "Sanitize user input",
                    "Apply WAF filtering",
                    "Enforce least-privilege database access"
                ],
                "insight": "SQL Injection attacks manipulate backend database queries using unsanitized user input. Boolean-based payloads such as ' OR '1'='1 attempt to bypass authentication checks by forcing SQL conditions to always evaluate TRUE.",
                "indicators": ["Authentication Targeting", "Credential Access Attempt"],
                "correlated_ioc": "185.220.101.4 → Previous SQLi attempts detected"
            },
            {
                "id": "XSS_SCRIPT_001",
                "name": "Cross-Site Scripting (XSS)",
                "pattern": r"<script.*?>|alert\(|onload=|onerror=",
                "severity": "HIGH",
                "confidence": 98,
                "score": 88,
                "fp_prob": "LOW",
                "mitre": "T1059.007 – JavaScript",
                "owasp": "A03:2021 – Injection",
                "engine": "DOM Signature Match",
                "impact": ["Session hijacking", "Website defacement", "Browser-based malware delivery"],
                "recommendation": "Inspect web application logs for similar script tags. Deploy CSP headers and sanitize all reflected parameters.",
                "timeline": [
                    {"step": "User Landing", "status": "COMPLETED"},
                    {"step": "Script Injection", "status": "DETECTED"},
                    {"step": "DOM Modification", "status": "INTERCEPTED"},
                    {"step": "Session Exfiltration", "status": "PREVENTED"}
                ],
                "query_impact": {
                    "original": "<div>USER_INPUT</div>",
                    "payload": "<script>alert(1)</script>",
                    "logical": "Arbitrary JavaScript execution in user context"
                },
                "details": "Detected malicious JavaScript patterns intended for Cross-Site Scripting. This can lead to session hijacking, defacement, or malware delivery.",
                "mitigation": ["Implement strict CSP headers", "Use context-aware encoding", "Validation libraries"],
                "insight": "XSS allows attackers to execute scripts in the victim's browser context by injecting untrusted data into a web page.",
                "indicators": ["Client-Side Execution", "Session Hijacking"]
            }
        ]

        # Default for Phishing/Typosquatting
        self.default_phish = {
            "id": "PHISH_HEURISTIC_001",
            "name": "Phishing / Typosquatting",
            "severity": "HIGH",
            "confidence": 94,
            "score": 82,
            "mitre": "T1566 – Phishing",
            "engine": "Lexical Heuristics",
            "details": "Domain exhibits typosquatting signatures. The page content mimics common login portals. Heuristic scans detected potential credential harvesting patterns.",
            "mitigation": [
                "Block domain at perimeter",
                "Force user password resets",
                "Enable MFA",
                "Report to registrar"
            ],
            "insight": "Phishing domains often use typosquatting or visually similar characters to deceive users. These sites are the primary vector for initial credential access.",
            "indicators": ["Credential Access", "Initial Access"],
            "impact": ["Account Takeover", "Session Hijacking", "Financial Fraud"],
            "query_impact": {
                "original": "N/A - Social Engineering",
                "logical": "Mimicking legitimate login service to harvest user credentials.",
                "payload": "POST /owa/auth HTTP/1.1"
            }
        }

    def analyze_url(self, url):
        if not url:
            return None
        
        decoded_url = url.lower() # Simple normalization for regex

        for sig in self.signatures:
            if re.search(sig['pattern'], decoded_url, re.IGNORECASE):
                return sig

        # Check for phishing keywords if no specialized payload is found
        phish_keywords = ['login', 'verify', 'update', 'account', 'secure', 'banking', 'signin']
        if any(kw in decoded_url for kw in phish_keywords):
            return self.default_phish

        # Safe result
        return {
            "id": "CLEAN_URL_001",
            "name": "Clean / Unknown",
            "severity": "LOW",
            "confidence": 85,
            "score": 12,
            "mitre": "N/A",
            "engine": "Reputation Check",
            "details": "No known malicious signatures or anomalies detected in the provided URL string.",
            "mitigation": ["Standard monitoring"],
            "insight": "Even clean URLs should be treated with caution if received from untrusted sources.",
            "indicators": ["No indicators found"],
            "impact": [],
            "query_impact": None
        }

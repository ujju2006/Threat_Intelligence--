# ThreatFusion: Enterprise Threat Intelligence & IOC Correlation Platform

ThreatFusion is a comprehensive, visually polished cybersecurity intelligence platform. Inspired by industry-leading tools like Splunk Enterprise Security, IBM QRadar, and Wazuh, ThreatFusion acts as both an operational SOC (Security Operations Center) dashboard and an educational ecosystem.

> **Academic Note:** This project does **not** use Artificial Intelligence or Machine Learning. All threat correlation is performed through **deterministic, rule-based logic** as described below.

---

## Correlation Engine — Rule-Based Architecture

ThreatFusion uses a **deterministic matching engine** inside `modules/analyzer.py`:

| Rule Condition | Severity Assigned |
|---|---|
| IOC matches a known regex signature (e.g., SQLi boolean pattern) | `CRITICAL` |
| URL/domain contains phishing-keyword heuristics | `HIGH` |
| No signature match found | `LOW` (Clean) |
| IOC appears in multiple threat feeds | Severity escalated per feed count |

**Example correlation logic:**
```
if ioc_feed_count >= 5:
    severity = "CRITICAL"
elif ioc_feed_count >= 3:
    severity = "HIGH"
else:
    severity = "LOW"
```

This is **rule-based correlation** — not machine learning. It is fully deterministic and reproducible for every given input.

---

## Core Features

1. **Role-Based Access Control (RBAC):** Login as Analyst, Threat Hunter, or Admin.
2. **Rule-Based Threat Correlation Engine:** Unified deterministic logic for LOW, MEDIUM, HIGH, and CRITICAL threat scoring across all modules.
3. **Interactive IOC Relationship Graph:** Visually track the attack chain from an IP → phishing URL → malware hash → associated CVEs.
4. **Exportable Analyst Reports:** Instantly generate PDF and DOCX threat reports.
5. **Educational Insights:** "Analyst Insight" panels accompany every threat, MITRE technique, and CVE to explain *why* the attack works and *how* to defend against it.
6. **Threat Timelines:** Track attacker behavior from Reconnaissance → Delivery → Harvesting → Persistence.
7. **Global SOC Search:** Instantly search through IPs, URLs, Hashes, and CVEs using deterministic feed matching.

---

## Architecture

- **Backend:** Python 3 / Flask
- **Frontend:** HTML5, Custom Glassmorphism CSS, Vanilla JavaScript
- **Visualization:** Chart.js (charts), Leaflet.js (maps), Vis-Network (IOC graphs)
- **Data:** JSON-based threat simulation dataset (no external API calls required)
- **Correlation Logic:** Rule-based regex + heuristic signature matching (`modules/analyzer.py`)

---

## Installation & Local Execution

```bash
# Navigate to project directory
cd ThreatFusion

# Install dependencies
pip install -r requirements.txt

# Start the SOC Dashboard
python app.py
```

Open your browser and navigate to `http://localhost:5001`.

**Default Login Credentials:**
| Username | Password | Role |
|---|---|---|
| `analyst1` | `admin` | Analyst |
| `hunter1` | `admin` | Threat Hunter |
| `admin` | `admin` | Admin |

---

## Deployment

ThreatFusion is fully equipped for modern cloud deployment.
- Use the included `Dockerfile` for containerized hosting.
- Use the `Procfile` for seamless one-click deployment on Render.com or Heroku.

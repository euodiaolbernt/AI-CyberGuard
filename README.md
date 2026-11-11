# AI CyberGuard

**Artificial Intelligence for Automated Cyber Threat Detection and Legal
Compliance Monitoring in Smart Urban Systems** — Final Year Project
prototype.

A modular Python/Streamlit application implementing the six-layer
architecture from the interim report: Data Sources → Collection &
Ingestion → Processing & Analysis (ML threat detection) → Compliance
Monitoring → Alerting & Response → Reporting & Visualization.

This is an educational FYP prototype. It does not control real
infrastructure, does not claim legal compliance, and does not perform
any live network blocking — see the "Scope" section of the project
brief.

## Current status

**Through Step 10 (Spiral Model Iteration 10) - all 8 pages are
functional.** Login/roles, Dashboard, Threat Detection (CSV upload →
validate → preprocess → train Random Forest/XGBoost/Isolation Forest
→ AI detection), URL Scanner (VirusTotal API v3), Compliance
Monitoring (PDPA/ISO 27001/NIST CSF/GDPR/EU AI Act rule engine),
Alerts & Incidents, Reports (date-range filtered summaries + CSV/PDF
export), Audit Logs, and Settings (admin user management).

Every number shown anywhere in the app is a live read from MySQL -
nothing is hard-coded or randomly generated. A HIGH/CRITICAL threat
detection or a MALICIOUS/SUSPICIOUS URL scan automatically flows
through the compliance engine and, above a risk score of 80, creates
an alert - see `compliance/compliance_engine.py` for the exact
pipeline.

## Setup

### 1. Python environment

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. MySQL database

Make sure MySQL Server is installed and running, then import the
schema (this also creates the `ai_cyberguard` database):

```bash
mysql -u root -p < database/schema.sql
```

### 3. Configure secrets

Copy `.env.example` to `.env` (already done for you in this scaffold —
just edit the values) and fill in your real MySQL password:

```
DB_PASSWORD=your_real_mysql_password
```

Set `VIRUSTOTAL_API_KEY` to a free key from
[virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
to enable the URL Scanner (it works without one, but scanning is
disabled with an explanatory message until it's set).

**If the app is already running when you edit `.env`, you must fully
stop and restart it** (`Ctrl+C` then `streamlit run app.py` again) -
`config.py` only reads `.env` once per process, so saving the file
alone or clicking Streamlit's "Rerun" has no effect on an already-running server.

### 4. Create the first admin account

```bash
python scripts/create_admin.py
```

You'll be prompted for a username and password (hidden input, never
written to source code). It's stored as a bcrypt hash in the `users`
table.

### 5. Run the app

```bash
streamlit run app.py
```

Open the URL Streamlit prints (usually http://localhost:8501) and log
in with the admin account you just created.

## Project structure

```
AI-CyberGuard/
├── app.py                  # entry point: login gate + sidebar router
├── config.py                # loads all secrets/config from .env
├── auth/                    # login, password hashing, session/roles
├── database/                # MySQL connection, schema.sql, queries
├── utils/                   # audit_logger.py (shared across features)
├── scripts/                 # create_admin.py (one-time setup)
├── app_pages/                # Dashboard, Threat Detection, URL Scanner, Compliance,
│                              # Alerts, Audit Logs, Settings (Reports still a placeholder)
│                              #   NOT named "pages/" - Streamlit reserves that
│                              #   folder name for its own auto-navigation, which
│                              #   would bypass our login/role checks entirely.
├── ml/                      # preprocessing/training/prediction/risk_scoring
├── compliance/               # compliance_engine.py + pdpa/iso27001/nist/gdpr/eu_ai_act rules
├── security/                 # VirusTotal URL scanning (validation/virustotal/url_scanner)
├── models/                   # trained_model.pkl files land here
└── data/                     # uploaded CSV datasets land here
```

## Roles

| Role | Access |
|---|---|
| ADMIN | Everything |
| SOC ANALYST | Dashboard, Threat Detection, URL Scanner, Alerts & Incidents, Reports |
| COMPLIANCE OFFICER | Dashboard, Compliance Monitoring, Reports, Audit Logs |
| AUDITOR | Dashboard, Compliance Monitoring, Reports, Audit Logs |

Defined in `auth/authentication.py` → `ROLE_PERMISSIONS`.

## Security notes

- Passwords are hashed with bcrypt (`auth/password.py`) — never stored
  in plain text.
- All secrets (DB credentials, VirusTotal key) live in `.env`, which is
  git-ignored; `config.py` is the only file that reads them.
- All SQL uses parameterised queries (`database/models.py`) — no
  string-built SQL.
- No sample/demo data or fake AI results are hard-coded anywhere; the
  Dashboard and detection pages will show "No data available" until
  you actually upload data or scan something, once those steps are built.

## Development roadmap (Spiral Model)

1. ✅ Login + project structure
2. ✅ Dashboard (KPIs, trend/distribution charts, compliance overview, recent tables)
3. ✅ CSV upload + validation/preprocessing
4. ✅ ML model training (Random Forest, XGBoost, Isolation Forest)
5. ✅ Automatic threat detection + risk scoring
6. ✅ URL scanner (VirusTotal API v3)
7. ✅ Compliance rule engine (PDPA, ISO/IEC 27001, NIST CSF, GDPR, EU AI Act)
8. ✅ Alerts & incident management
9. ✅ Audit logs
10. ✅ Reports (date-range filtered summaries + CSV/PDF export)
11. ⬜ Full integration testing - in progress

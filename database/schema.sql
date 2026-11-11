-- ==================================================================
-- AI CyberGuard - MySQL schema
--
-- Run once against a fresh MySQL server to create the database and
-- all tables:
--
--     mysql -u root -p < database/schema.sql
--
-- The full schema is created up-front (per the FYP report's data
-- design) even though early development steps only use `users` and
-- `audit_logs` - later steps populate the rest as each feature
-- (ML detection, URL scanning, compliance, alerts, reports) is built.
-- ==================================================================

CREATE DATABASE IF NOT EXISTS ai_cyberguard
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE ai_cyberguard;

-- ------------------------------------------------------------------
-- users : application accounts and roles
--
-- email/auth_provider were added for Google OAuth self-signup
-- (Step "Login System Update"). password_hash is nullable because a
-- Google-authenticated account has no local password at all -
-- authentication for that account happens entirely through Google,
-- never through this column. `username` stays the app-wide identity
-- key everything else (session_state, audit_logs.username, etc.)
-- already uses; for new self-registered accounts (email or Google)
-- it's simply set equal to the email, so every existing username-keyed
-- code path keeps working unchanged. Existing ADMIN/SOC ANALYST/
-- COMPLIANCE OFFICER/AUDITOR accounts are untouched by this - 'USER'
-- is only ever the default for a brand-new self-registered account.
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(255) NOT NULL UNIQUE,     -- matches email's own length: self-registration sets username = email
    email           VARCHAR(255) NULL UNIQUE,
    password_hash   VARCHAR(255) NULL,               -- bcrypt hash; NULL for Google-only accounts
    role            ENUM('ADMIN','SOC ANALYST','COMPLIANCE OFFICER','AUDITOR','USER') NOT NULL DEFAULT 'USER',
    auth_provider   ENUM('local','google') NOT NULL DEFAULT 'local',
    full_name       VARCHAR(100) DEFAULT '',
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    last_login      DATETIME     NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------------
-- network_traffic : uploaded CSV datasets (Layer 2 ingestion)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_traffic (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    dataset_name    VARCHAR(150) NOT NULL,
    uploaded_by     INT NULL,
    row_count       INT NOT NULL DEFAULT 0,
    column_count    INT NOT NULL DEFAULT 0,
    uploaded_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status          ENUM('UPLOADED','VALIDATED','PREPROCESSED','PROCESSED','ERROR') NOT NULL DEFAULT 'UPLOADED',
    storage_path    VARCHAR(255) NULL,
    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
);

-- ------------------------------------------------------------------
-- threat_detections : one row per AI prediction (Layer 3)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_detections (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NULL,                         -- owner (multi-tenant data isolation)
    traffic_id      INT NULL,
    record_index    INT NULL,                        -- row number within the source dataset
    prediction      ENUM('BENIGN','MALICIOUS') NOT NULL,
    attack_type     VARCHAR(100) NULL,
    confidence      DECIMAL(5,2) NULL,                -- 0.00 - 100.00 (%)
    risk_score      INT NULL,                         -- 0 - 100
    severity        ENUM('LOW','MEDIUM','HIGH','CRITICAL') NULL,
    model_used      VARCHAR(50) NULL,                 -- RandomForest / XGBoost / IsolationForest
    detected_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (traffic_id) REFERENCES network_traffic(id) ON DELETE SET NULL
);

-- ------------------------------------------------------------------
-- url_scan_results : VirusTotal-backed URL threat intelligence
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS url_scan_results (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    url                 VARCHAR(2048) NOT NULL,
    scanned_by          INT NULL,
    scan_timestamp      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scan_status         ENUM('SAFE','SUSPICIOUS','MALICIOUS','SCAN_ERROR') NOT NULL,
    threat_category     VARCHAR(100) NULL,
    detection_count     INT NULL,
    total_engines       INT NULL,
    risk_score          INT NULL,
    risk_level          ENUM('LOW','MEDIUM','HIGH','CRITICAL') NULL,
    source              VARCHAR(50) NOT NULL DEFAULT 'VirusTotal',
    analysis_reference  VARCHAR(255) NULL,             -- VT analysis/report id, for traceability
    FOREIGN KEY (scanned_by) REFERENCES users(id) ON DELETE SET NULL
);

-- ------------------------------------------------------------------
-- compliance_rules : predefined prototype rules per framework (Layer 4)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_rules (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    framework           ENUM('PDPA','ISO27001','NIST_CSF','GDPR','EU_AI_ACT') NOT NULL,
    rule_code           VARCHAR(50) NOT NULL UNIQUE,
    title               VARCHAR(200) NOT NULL,
    description         TEXT NULL,
    trigger_condition   VARCHAR(255) NULL,             -- human-readable condition this rule checks
    recommended_action  TEXT NULL
);

-- ------------------------------------------------------------------
-- compliance_results : outcome of evaluating one rule against one event
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_results (
    id                      INT AUTO_INCREMENT PRIMARY KEY,
    user_id                 INT NULL,                 -- owner (multi-tenant data isolation)
    rule_id                 INT NOT NULL,
    related_detection_id    INT NULL,
    related_url_scan_id     INT NULL,
    status                  ENUM('COMPLIANT','NEEDS_REVIEW','POTENTIAL_VIOLATION') NOT NULL,
    reason                  TEXT NULL,
    evidence                TEXT NULL,
    recommended_action      TEXT NULL,
    checked_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (rule_id) REFERENCES compliance_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (related_detection_id) REFERENCES threat_detections(id) ON DELETE SET NULL,
    FOREIGN KEY (related_url_scan_id) REFERENCES url_scan_results(id) ON DELETE SET NULL
);

-- ------------------------------------------------------------------
-- alerts : high-risk events surfaced for SOC / compliance follow-up (Layer 5)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id                      INT AUTO_INCREMENT PRIMARY KEY,
    user_id                 INT NULL,                      -- owner (multi-tenant data isolation)
    threat_ref              VARCHAR(30) NOT NULL UNIQUE,   -- e.g. THR-0021
    event_type              VARCHAR(50) NOT NULL,          -- e.g. "Network Threat" / "Malicious URL"
    threat_type             VARCHAR(100) NULL,
    severity                ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    risk_score              INT NOT NULL,
    confidence              DECIMAL(5,2) NULL,
    related_detection_id    INT NULL,
    related_url_scan_id     INT NULL,
    compliance_summary      TEXT NULL,
    recommended_action      TEXT NULL,
    status                  ENUM('NEW','INVESTIGATING','RESOLVED') NOT NULL DEFAULT 'NEW',
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (related_detection_id) REFERENCES threat_detections(id) ON DELETE SET NULL,
    FOREIGN KEY (related_url_scan_id) REFERENCES url_scan_results(id) ON DELETE SET NULL
);

-- ------------------------------------------------------------------
-- audit_logs : full activity trail (Layer 6 / accountability)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(255) NOT NULL,      -- matches users.username's own length
    action          VARCHAR(50) NOT NULL,       -- e.g. LOGIN, URL_SCAN, ALERT_CREATED
    event_type      VARCHAR(50) NULL,
    description     TEXT NULL,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------------
-- rate_limit_counters : persistent, atomic counters backing login
-- brute-force throttling (auth/rate_limit.py) and the URL scanner's
-- per-user cooldown (security/url_scanner.py). A row's `scope` names
-- which limiter it belongs to (e.g. 'LOGIN_ACCOUNT', 'LOGIN_SOURCE',
-- 'URL_SCAN_USER'); `identifier` is that scope's own key (a
-- normalized account name, a source IP, or a user id as text).
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limit_counters (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scope           VARCHAR(20) NOT NULL,
    identifier      VARCHAR(255) NOT NULL,
    attempt_count   INT NOT NULL DEFAULT 1,
    window_start    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_until    DATETIME NULL,
    UNIQUE KEY uq_rate_limit_scope_identifier (scope, identifier)
);

-- ------------------------------------------------------------------
-- reports : generated report metadata (Layer 6 export)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    generated_by    INT NULL,
    report_type     VARCHAR(50) NOT NULL,        -- e.g. "Threat Summary", "Compliance Summary"
    file_format     ENUM('CSV','PDF') NOT NULL,
    file_path       VARCHAR(255) NULL,
    generated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL
);

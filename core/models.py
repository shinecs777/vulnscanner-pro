"""Database schema and initialization for VulnScanner Pro."""

from core.database import get_db

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    limitations TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL
        REFERENCES assessments(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    product TEXT,
    version TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL
        REFERENCES assessments(id) ON DELETE CASCADE,
    asset_id INTEGER
        REFERENCES assets(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL
        CHECK (finding_type IN (
            'informational', 'misconfiguration', 'potential_vuln', 'confirmed_vuln'
        )),
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    risk_level TEXT NOT NULL
        CHECK (risk_level IN ('Info', 'Low', 'Medium', 'High', 'Critical')),
    confidence TEXT NOT NULL
        CHECK (confidence IN ('low', 'medium', 'high')),
    risk_reasoning TEXT,
    recommendation TEXT,
    requires_verification INTEGER NOT NULL DEFAULT 1
        CHECK (requires_verification IN (0, 1)),
    fingerprint TEXT NOT NULL,
    remediation_status TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (assessment_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS cve_records (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    published TEXT,
    references_json TEXT,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS finding_cves (
    finding_id INTEGER NOT NULL
        REFERENCES findings(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL
        REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    is_confirmed INTEGER NOT NULL DEFAULT 0
        CHECK (is_confirmed IN (0, 1)),
    PRIMARY KEY (finding_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_assessments_started_at
    ON assessments(started_at);
CREATE INDEX IF NOT EXISTS idx_assets_assessment_id
    ON assets(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_assessment_id
    ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id
    ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_finding_cves_cve_id
    ON finding_cves(cve_id);
"""


def init_db() -> None:
    """Create all tables and indexes if they do not already exist."""
    with get_db() as connection:
        connection.executescript(SCHEMA)

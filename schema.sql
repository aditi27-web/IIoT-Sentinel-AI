PRAGMA foreign_keys = ON;
CREATE TABLE devices (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, device_type TEXT NOT NULL,
 location TEXT, status TEXT NOT NULL DEFAULT 'Monitored', created_at TEXT NOT NULL
);
CREATE TABLE vulnerabilities (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, cve_id TEXT, title TEXT NOT NULL,
 service TEXT, port INTEGER, cvss REAL NOT NULL, is_public INTEGER NOT NULL DEFAULT 0,
 patch_available INTEGER NOT NULL DEFAULT 0, known_exploit INTEGER NOT NULL DEFAULT 0,
 asset_criticality INTEGER NOT NULL DEFAULT 2, predicted_severity TEXT NOT NULL,
 model_name TEXT NOT NULL, recommendation TEXT NOT NULL, mitigation_cost REAL NOT NULL,
 mitigation_benefit REAL NOT NULL, cba_score REAL NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
);
CREATE TABLE predictions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id INTEGER NOT NULL, model_name TEXT NOT NULL,
 predicted_severity TEXT NOT NULL, confidence REAL, created_at TEXT NOT NULL,
 FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);
CREATE TABLE mitigation_actions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id INTEGER NOT NULL, action TEXT NOT NULL,
 estimated_cost REAL NOT NULL, estimated_benefit REAL NOT NULL, cba_score REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'Recommended', created_at TEXT NOT NULL,
 FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

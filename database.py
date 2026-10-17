import sqlite3, os
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "iiot_sentinel.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      device_type TEXT NOT NULL,
      location TEXT,
      status TEXT NOT NULL DEFAULT 'Monitored',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER,
      cve_id TEXT,
      title TEXT NOT NULL,
      service TEXT,
      port INTEGER,
      cvss REAL NOT NULL,
      is_public INTEGER NOT NULL DEFAULT 0,
      patch_available INTEGER NOT NULL DEFAULT 0,
      known_exploit INTEGER NOT NULL DEFAULT 0,
      asset_criticality INTEGER NOT NULL DEFAULT 2,
      predicted_severity TEXT NOT NULL,
      model_name TEXT NOT NULL,
      recommendation TEXT NOT NULL,
      mitigation_cost REAL NOT NULL,
      mitigation_benefit REAL NOT NULL,
      cba_score REAL NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS predictions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vulnerability_id INTEGER NOT NULL,
      model_name TEXT NOT NULL,
      predicted_severity TEXT NOT NULL,
      confidence REAL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS mitigation_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vulnerability_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      estimated_cost REAL NOT NULL,
      estimated_benefit REAL NOT NULL,
      cba_score REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'Recommended',
      created_at TEXT NOT NULL,
      FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    );
    """)
    count = db.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"]
    if count == 0:
        from datetime import datetime
        now = datetime.now().isoformat(timespec="seconds")
        db.executemany("INSERT INTO devices(name,device_type,location,status,created_at) VALUES(?,?,?,?,?)", [
            ("Boiler Sensor A", "Sensor", "Plant Zone A", "Monitored", now),
            ("Production Gateway", "IIoT Gateway", "Plant Zone B", "Monitored", now),
            ("Control Router 01", "Router", "Network Cabinet", "Monitored", now),
            ("Quality Server", "Server", "Control Room", "Monitored", now)])
    count_v = db.execute("SELECT COUNT(*) n FROM vulnerabilities").fetchone()["n"]
    if count_v == 0:
        from datetime import datetime
        now = datetime.now().isoformat(timespec="seconds")
        samples = [
        ("DEMO-CVE-001","Outdated gateway firmware","http",8080,9.1,1,1,1,3,"Critical","Gradient Boosting","Patch firmware; validate backup and maintenance window",5500,9500),
        ("DEMO-CVE-002","Unrestricted remote service","ssh",22,8.2,1,1,1,3,"High","Gradient Boosting","Restrict remote access; require strong authentication",3000,7000),
        ("DEMO-CVE-003","Missing security update","https",443,6.4,0,1,0,2,"Medium","Gradient Boosting","Apply tested security update during maintenance",1200,3000),
        ("DEMO-CVE-004","Excessive service exposure","modbus",502,4.2,0,0,0,2,"Low","Gradient Boosting","Limit service exposure to trusted network segments",800,1400)]
        for i,s in enumerate(samples):
            db.execute("""INSERT INTO vulnerabilities(device_id,cve_id,title,service,port,cvss,is_public,patch_available,
                known_exploit,asset_criticality,predicted_severity,model_name,recommendation,mitigation_cost,mitigation_benefit,cba_score,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (i+1,*s, s[-1] / s[-2], now))
    db.commit()
    db.close()

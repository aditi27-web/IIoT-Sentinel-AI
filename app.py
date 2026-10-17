from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from database import init_db, get_db
from ml.model import train_models, predict_severity, MODEL_PATH
from ml.recommendations import recommendation_for, cba_score
import csv, io, os, json
from datetime import datetime

app = Flask(__name__)
app.secret_key = "change-this-development-secret"
init_db()
train_models()

@app.route("/")
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) n FROM vulnerabilities").fetchone()["n"]
    critical = db.execute("SELECT COUNT(*) n FROM vulnerabilities WHERE predicted_severity='Critical'").fetchone()["n"]
    high = db.execute("SELECT COUNT(*) n FROM vulnerabilities WHERE predicted_severity='High'").fetchone()["n"]
    devices = db.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"]
    rows = db.execute("""SELECT v.*, d.name AS device_name
        FROM vulnerabilities v LEFT JOIN devices d ON v.device_id=d.id
        ORDER BY CASE v.predicted_severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
        v.created_at DESC LIMIT 8""").fetchall()
    severity = db.execute("""SELECT predicted_severity AS label, COUNT(*) AS value
        FROM vulnerabilities GROUP BY predicted_severity""").fetchall()
    return render_template("dashboard.html", total=total, critical=critical, high=high,
                           devices=devices, rows=rows, severity=[dict(x) for x in severity])

@app.route("/vulnerabilities")
def vulnerabilities():
    db = get_db()
    rows = db.execute("""SELECT v.*, d.name AS device_name FROM vulnerabilities v
        LEFT JOIN devices d ON v.device_id=d.id ORDER BY v.created_at DESC""").fetchall()
    return render_template("vulnerabilities.html", rows=rows)

@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    if request.method == "POST":
        try:
            data = {
                "cvss": float(request.form.get("cvss", 5)),
                "port": int(request.form.get("port", 0)),
                "is_public": int(request.form.get("is_public", 0)),
                "patch_available": int(request.form.get("patch_available", 0)),
                "known_exploit": int(request.form.get("known_exploit", 0)),
                "asset_criticality": int(request.form.get("asset_criticality", 2)),
                "service": request.form.get("service", "unknown"),
            }
            model_name = request.form.get("model", "Gradient Boosting")
            severity = predict_severity(data, model_name)
            action, cost, benefit = recommendation_for(severity, data)
            score = cba_score(benefit, cost)
            db = get_db()
            cur = db.execute("""INSERT INTO vulnerabilities
                (device_id, cve_id, title, service, port, cvss, is_public, patch_available,
                 known_exploit, asset_criticality, predicted_severity, model_name, recommendation,
                 mitigation_cost, mitigation_benefit, cba_score, created_at)
                VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (request.form.get("cve_id", "DEMO-NEW"), request.form.get("title", "Manual assessment"),
                 data["service"], data["port"], data["cvss"], data["is_public"], data["patch_available"],
                 data["known_exploit"], data["asset_criticality"], severity, model_name, action,
                 cost, benefit, score, datetime.now().isoformat(timespec="seconds")))
            vid = cur.lastrowid
            db.execute("INSERT INTO predictions (vulnerability_id, model_name, predicted_severity, created_at) VALUES (?, ?, ?, ?)",
                       (vid, model_name, severity, datetime.now().isoformat(timespec="seconds")))
            db.commit()
            flash(f"Assessment saved. Predicted severity: {severity}. CBA score: {score:.2f}", "success")
            return redirect(url_for("vulnerability_detail", vid=vid))
        except Exception as e:
            flash("Could not analyze this record: " + str(e), "error")
    return render_template("analyze.html")

@app.route("/vulnerability/<int:vid>")
def vulnerability_detail(vid):
    db = get_db()
    row = db.execute("""SELECT v.*, d.name AS device_name FROM vulnerabilities v
        LEFT JOIN devices d ON v.device_id=d.id WHERE v.id=?""", (vid,)).fetchone()
    if not row:
        flash("Record not found.", "error")
        return redirect(url_for("vulnerabilities"))
    return render_template("detail.html", row=row)

@app.route("/devices")
def devices():
    db = get_db()
    rows = db.execute("SELECT d.*, COUNT(v.id) AS issue_count FROM devices d LEFT JOIN vulnerabilities v ON v.device_id=d.id GROUP BY d.id ORDER BY d.id DESC").fetchall()
    return render_template("devices.html", rows=rows)

@app.route("/devices/add", methods=["POST"])
def add_device():
    name = request.form.get("name", "").strip()
    device_type = request.form.get("device_type", "Gateway").strip()
    location = request.form.get("location", "Demo factory").strip()
    if name:
        db = get_db()
        db.execute("INSERT INTO devices (name, device_type, location, status, created_at) VALUES (?, ?, ?, 'Monitored', ?)",
                   (name, device_type, location, datetime.now().isoformat(timespec="seconds")))
        db.commit()
        flash("Device added.", "success")
    return redirect(url_for("devices"))

@app.route("/import", methods=["GET", "POST"])
def import_csv():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename.lower().endswith(".csv"):
            flash("Choose a CSV file.", "error")
            return redirect(url_for("import_csv"))
        text = io.StringIO(file.stream.read().decode("utf-8-sig"))
        reader = csv.DictReader(text)
        required = {"cvss", "port", "is_public", "patch_available", "known_exploit", "asset_criticality"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            flash("CSV needs columns: " + ", ".join(sorted(required)), "error")
            return redirect(url_for("import_csv"))
        db = get_db()
        count = 0
        for r in reader:
            try:
                data = {"cvss": float(r["cvss"]), "port": int(r["port"]), "is_public": int(r["is_public"]),
                        "patch_available": int(r["patch_available"]), "known_exploit": int(r["known_exploit"]),
                        "asset_criticality": int(r["asset_criticality"]), "service": r.get("service", "unknown")}
                model_name = "Gradient Boosting"
                severity = predict_severity(data, model_name)
                action, cost, benefit = recommendation_for(severity, data)
                db.execute("""INSERT INTO vulnerabilities
                    (device_id,cve_id,title,service,port,cvss,is_public,patch_available,known_exploit,asset_criticality,
                    predicted_severity,model_name,recommendation,mitigation_cost,mitigation_benefit,cba_score,created_at)
                    VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (r.get("cve_id", "IMPORTED"), r.get("title", "Imported CSV record"), data["service"], data["port"],
                     data["cvss"], data["is_public"], data["patch_available"], data["known_exploit"],
                     data["asset_criticality"], severity, model_name, action, cost, benefit, cba_score(benefit,cost),
                     datetime.now().isoformat(timespec="seconds")))
                count += 1
            except (ValueError, KeyError):
                continue
        db.commit()
        flash(f"Imported and analyzed {count} rows.", "success")
        return redirect(url_for("vulnerabilities"))
    return render_template("import.html")

@app.route("/api/summary")
def api_summary():
    db = get_db()
    counts = db.execute("SELECT predicted_severity, COUNT(*) AS count FROM vulnerabilities GROUP BY predicted_severity").fetchall()
    return jsonify({r["predicted_severity"]: r["count"] for r in counts})

if __name__ == "__main__":
    app.run(debug=True)

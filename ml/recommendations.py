def recommendation_for(severity, data):
    # Illustrative estimates only; replace with verified organizational costs.
    if data.get("known_exploit") or severity == "Critical":
        return ("Isolate affected asset if operationally safe; apply vendor-approved patch; verify backups and monitor.", 5500.0, 12000.0)
    if severity == "High":
        return ("Restrict access, apply vendor-approved updates, and validate network segmentation.", 3000.0, 7000.0)
    if severity == "Medium":
        return ("Schedule tested security updates and review service exposure.", 1200.0, 3000.0)
    return ("Harden configuration, disable unnecessary services, and monitor logs.", 800.0, 1400.0)

def cba_score(benefit, cost):
    return round(float(benefit) / max(float(cost), 1.0), 2)

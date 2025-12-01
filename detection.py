# detection.py
from datetime import datetime, timedelta
from database import fetch_recent_logs, insert_alert, get_last_alert_time

BRUTE_WINDOW = 120
BRUTE_THRESHOLD = 5
STUFF_WINDOW = 120
STUFF_THRESHOLD = 2
COOLDOWN = 300  # seconds

# in-memory cooldown dictionaries - track per alert key to prevent duplicates
_last_alerts = {}  # (alert_type, key) -> datetime

def run_detection_once():
    now = datetime.utcnow()
    logs = fetch_recent_logs(1000)

    # BRUTE FORCE: count failed attempts per IP in window
    ip_counts = {}
    for row in logs:
        username, ip, status, ts = row
        try:
            t = datetime.fromisoformat(ts)
        except Exception:
            continue
        if (now - t).total_seconds() <= BRUTE_WINDOW and status.startswith("fail"):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for ip, count in ip_counts.items():
        if count >= BRUTE_THRESHOLD:
            alert_key = ("BRUTE_FORCE", ip)
            last = _last_alerts.get(alert_key)
            # Use generic message (without count) so DB dedup works across different count values
            details = f"Brute force attack detected from IP {ip}"
            db_last_ts = get_last_alert_time("BRUTE_FORCE", details)
            db_ok = True
            if db_last_ts:
                try:
                    db_last = datetime.fromisoformat(db_last_ts)
                    if (now - db_last).total_seconds() <= COOLDOWN:
                        db_ok = False
                except Exception:
                    pass
            if (not last or (now - last).total_seconds() > COOLDOWN) and db_ok:
                insert_alert("BRUTE_FORCE", details)
                _last_alerts[alert_key] = now

    # CREDENTIAL STUFFING: count usernames that failed with attempts from same IP
    # Multiple users targeted from same IP suggests credential stuffing
    failed_logs = []
    for row in logs:
        username, ip, status, ts = row
        try:
            t = datetime.fromisoformat(ts)
        except Exception:
            continue
        if (now - t).total_seconds() <= STUFF_WINDOW and status.startswith("fail"):
            failed_logs.append((username, ip))
    
    # Group by IP: multiple failed logins to different users from same IP suggests stuffing
    ip_users = {}
    for username, ip in failed_logs:
        ip_users.setdefault(ip, set()).add(username)
    
    for ip, users in ip_users.items():
        if len(users) >= STUFF_THRESHOLD:
            alert_key = ("CREDENTIAL_STUFFING", ip)
            last = _last_alerts.get(alert_key)
            # Use generic message (without count) so DB dedup works across different user counts
            details = f"Credential stuffing attack detected from IP {ip}"
            db_last_ts = get_last_alert_time("CREDENTIAL_STUFFING", details)
            db_ok = True
            if db_last_ts:
                try:
                    db_last = datetime.fromisoformat(db_last_ts)
                    if (now - db_last).total_seconds() <= COOLDOWN:
                        db_ok = False
                except Exception:
                    pass
            if (not last or (now - last).total_seconds() > COOLDOWN) and db_ok:
                insert_alert("CREDENTIAL_STUFFING", details)
                _last_alerts[alert_key] = now

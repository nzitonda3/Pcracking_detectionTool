# detection.py
import time
from datetime import datetime
from database import fetch_recent_logs, insert_alert

# thresholds
BRUTE_FORCE_WINDOW = 120  # seconds
BRUTE_FORCE_THRESHOLD = 5
STUFFING_WINDOW = 120
STUFFING_THRESHOLD = 3

# cooldowns to avoid spamming alerts
brute_cooldown = {}   # ip -> last alert ts
stuffing_cooldown = {}  # fingerprint -> last alert ts
COOLDOWN_SECONDS = 300

def run_detection_once():
    now = datetime.utcnow()
    logs = fetch_recent_logs(500)

    # BRUTE FORCE detection: count failed attempts per IP within window
    ip_map = {}
    for username, ip, status, fp, ts in logs:
        try:
            t = datetime.fromisoformat(ts)
        except Exception:
            continue
        if (now - t).total_seconds() <= BRUTE_FORCE_WINDOW:
            if status.startswith("fail"):
                ip_map[ip] = ip_map.get(ip, 0) + 1

    for ip, count in ip_map.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            last = brute_cooldown.get(ip)
            if not last or (now - last).total_seconds() > COOLDOWN_SECONDS:
                insert_alert("BRUTE_FORCE", f"Detected {count} failed attempts from IP {ip}")
                brute_cooldown[ip] = now

    # CREDENTIAL STUFFING: same fingerprint across multiple usernames
    fp_map = {}
    for username, ip, status, fp, ts in logs:
        try:
            t = datetime.fromisoformat(ts)
        except Exception:
            continue
        if (now - t).total_seconds() <= STUFFING_WINDOW:
            fp_map.setdefault(fp, set()).add(username)

    for fp, users in fp_map.items():
        if len(users) >= STUFFING_THRESHOLD:
            last = stuffing_cooldown.get(fp)
            if not last or (now - last).total_seconds() > COOLDOWN_SECONDS:
                insert_alert("CREDENTIAL_STUFFING", f"Same password used on accounts: {', '.join(list(users)[:10])}")
                stuffing_cooldown[fp] = now

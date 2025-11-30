# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from database import init_db, insert_user, get_user_by_username, insert_pcfg, insert_jtr_result, fetch_recent_logs, fetch_recent_alerts, fetch_pcfg_rows, fetch_jtr_rows, list_users, store_plaintext, delete_plaintext_for_user
from utils import hash_password, verify_password, fingerprint_password
from pcfg_utils import analyze_and_store, estimate_guesses, identify_pattern
from jtr_utils import run_full_audit_all_users, run_jtr_on_hash
from detection import run_detection_once
from simulate_engine import simulate
import threading
import time

app = Flask(__name__)
app.secret_key = "replace_with_a_real_secret_in_prod"

# initialize DB
init_db()

# start a background detection loop (daemon)
def detection_background_loop():
    while True:
        try:
            run_detection_once()
        except Exception as e:
            print("Detection loop error:", e)
        time.sleep(5)

t = threading.Thread(target=detection_background_loop, daemon=True)
t.start()

# ---------- Routes ----------
@app.route("/")
def index():
    return redirect(url_for("login"))

# signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        if not username or not password:
            flash("username and password required", "error")
            return redirect(url_for("signup"))
        # create
        ph = hash_password(password)
        try:
            uid = insert_user(username, ph)
        except Exception as e:
            flash("username exists", "error")
            return redirect(url_for("signup"))

        # store plaintext temporarily for PCFG analysis
        store_plaintext(uid, password)
        # run pcfg analysis and store
        analyze_and_store(uid, password)
        # delete plaintext
        delete_plaintext_for_user(uid)

        flash("account created — you may login", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

# login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        ip = request.headers.get("X-Forwarded-For") or request.remote_addr

        row = get_user_by_username(username)
        if not row:
            # log failed attempt
            from database import insert_login_log
            insert_login_log(username, ip, "fail_no_user", fingerprint_password(password))
            flash("invalid credentials", "error")
            return redirect(url_for("login"))

        user_id, uname, stored_hash = row
        if not verify_password(password, stored_hash):
            from database import insert_login_log
            insert_login_log(username, ip, "fail_wrong_password", fingerprint_password(password))
            flash("invalid credentials", "error")
            return redirect(url_for("login"))

        # success
        from database import insert_login_log
        insert_login_log(username, ip, "success", fingerprint_password(password))
        session["user_id"] = user_id
        session["username"] = username
        # for demo: if username == 'admin' treat as admin
        if username == "admin":
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("login successful", "success")
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("logged out", "info")
    return redirect(url_for("login"))

# admin dashboard
@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        flash("admin only", "error")
        return redirect(url_for("login"))

    pcfg = fetch_pcfg_rows()
    jtr = fetch_jtr_rows()
    alerts = fetch_recent_alerts(50)
    logs = fetch_recent_logs(200)
    return render_template("admin_dashboard.html", pcfg=pcfg, jtr=jtr, alerts=alerts, logs=logs)

# run jtr audit for all users (button)
@app.route("/run_audit", methods=["POST"])
def run_audit():
    if not session.get("is_admin"):
        flash("admin only", "error")
        return redirect(url_for("login"))
    # run audits for all users (this will be slow because it runs per user up to 30s)
    # run in background thread to avoid blocking UI
    def worker():
        try:
            run_full_audit_all_users()
        except Exception as e:
            print("Audit worker error:", e)
    th = threading.Thread(target=worker, daemon=True)
    th.start()
    flash("audit started (runs in background)", "info")
    return redirect(url_for("admin_dashboard"))

# simulate attack page
@app.route("/simulate", methods=["GET", "POST"])
def simulate_attack():
    if not session.get("is_admin"):
        flash("admin only", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        attack_type = request.form.get("attack_type")
        usernames = [u.strip() for u in request.form.get("usernames","").split(",") if u.strip()]
        passwords = [p.strip() for p in request.form.get("passwords","").split(",") if p.strip()]
        ip = request.form.get("ip") or "1.2.3.4"
        count = int(request.form.get("count") or 3)
        # run simulation in background
        def sim_worker():
            try:
                simulate(attack_type, usernames, passwords, ip, count)
            except Exception as e:
                print("simulate error:", e)
        threading.Thread(target=sim_worker, daemon=True).start()
        flash("simulation started", "info")
        return redirect(url_for("admin_dashboard"))
    return render_template("simulate_attack.html")

# password checker form (PCFG instant)
@app.route("/check_password", methods=["GET", "POST"])
def check_password():
    result = None
    if request.method == "POST":
        pwd = request.form.get("password","")
        guesses, pattern = estimate_guesses(pwd)
        result = {"guesses": guesses, "pattern": pattern}
    return render_template("check_password.html", result=result)

# API endpoints for AJAX (optional)
@app.route("/api/logs")
def api_logs():
    rows = fetch_recent_logs(200)
    out = []
    for r in rows:
        out.append({"username": r[0], "ip": r[1], "status": r[2], "fingerprint": r[3], "timestamp": r[4]})
    return jsonify(out)

@app.route("/api/alerts")
def api_alerts():
    rows = fetch_recent_alerts(100)
    out = []
    for r in rows:
        out.append({"type": r[0], "details": r[1], "timestamp": r[2]})
    return jsonify(out)

if __name__ == "__main__":
    # ensure admin user exists for dashboard demo
    try:
        insert_user("admin", hash_password("AdminPass123!"))
    except Exception:
        pass
    app.run(host="0.0.0.0", port=5000, debug=True)

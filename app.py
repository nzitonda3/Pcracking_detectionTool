# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from database import init_db, insert_user, get_user_by_username, store_plaintext, delete_plaintext_for_user, fetch_pcfg_rows, fetch_jtr_rows, fetch_recent_alerts, fetch_recent_logs, insert_login_log, set_config, get_config
from utils import hash_password_sha512, verify_password_sha512, fingerprint_password
from pcfg_utils import analyze_and_store, estimate_guesses
from jtr_utils import run_full_audit_all_users
from detection import run_detection_once
from simulate_engine import simulate
import threading, time, os, tempfile

app = Flask(__name__)
app.secret_key = "replace_this_secret"

# ensure DB
init_db()

# start detection background loop
def detection_loop():
    while True:
        try:
            run_detection_once()
        except Exception as e:
            print("detection error:", e)
        time.sleep(5)

t = threading.Thread(target=detection_loop, daemon=True)
t.start()

# ensure admin exists: username 'admin' with password 'AdminPass123!' (SHA512)
try:
    if not get_user_by_username("admin"):
        insert_user("admin", hash_password_sha512("AdminPass123!"))
except Exception:
    pass

# ----- ROUTES -----
@app.route("/")
def index():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        if not username or not password:
            flash("username and password required", "error")
            return redirect(url_for("signup"))
        # create user (store sha512)
        ph = hash_password_sha512(password)
        try:
            uid = insert_user(username, ph)
        except Exception as e:
            flash("username exists", "error")
            return redirect(url_for("signup"))

        # store plaintext temporarily to run PCFG, then delete
        store_plaintext(uid, password)
        analyze_and_store(uid, password)
        delete_plaintext_for_user(uid)

        flash("account created", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        ip = request.headers.get("X-Forwarded-For") or request.remote_addr

        row = get_user_by_username(username)
        fingerprint = fingerprint_password(password)

        if not row:
            # log fail, single increment
            insert_login_log(username, ip, "fail_no_user", fingerprint)
            flash("invalid credentials", "error")
            return redirect(url_for("login"))

        user_id, uname, stored_hash = row
        if not verify_password_sha512(password, stored_hash):
            insert_login_log(username, ip, "fail_wrong_password", fingerprint)
            flash("invalid credentials", "error")
            return redirect(url_for("login"))

        # success
        insert_login_log(username, ip, "success", fingerprint)
        session["user_id"] = user_id
        session["username"] = username
        if username == "admin":
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("login successful", "success")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("logged out", "info")
    return redirect(url_for("login"))

@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        flash("admin only", "error")
        return redirect(url_for("login"))
    pcfg = fetch_pcfg_rows()
    jtr = fetch_jtr_rows()
    alerts = fetch_recent_alerts(100)
    logs = fetch_recent_logs(200)
    return render_template("admin_dashboard.html", pcfg=pcfg, jtr=jtr, alerts=alerts, logs=logs)

# run full audit in a background thread
@app.route("/run_audit", methods=["POST"])
def run_audit():
    if not session.get("is_admin"):
        flash("admin only", "error")
        return redirect(url_for("login"))
    def worker():
        try:
            run_full_audit_all_users()
        except Exception as e:
            print("audit error:", e)
    threading.Thread(target=worker, daemon=True).start()
    flash("audit started (30s per user cap)", "info")
    return redirect(url_for("admin_dashboard"))

# simulate page and file upload (wordlist)
@app.route("/simulate", methods=["GET","POST"])
def simulate_page():
    if not session.get("is_admin"):
        flash("admin only", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        attack_type = request.form.get("attack_type")
        usernames = [u.strip() for u in request.form.get("usernames","").split(",") if u.strip()]
        passwords = [p.strip() for p in request.form.get("passwords","").split(",") if p.strip()]
        ip = request.form.get("ip") or "1.2.3.4"
        count = int(request.form.get("count") or 3)

        # handle uploaded file
        wordlist_file = None
        f = request.files.get("wordlist")
        if f and f.filename:
            tmpdir = tempfile.gettempdir()
            path = os.path.join(tmpdir, f.filename)
            f.save(path)
            wordlist_file = path

        def worker():
            try:
                simulate(attack_type, usernames, passwords, ip, count, wordlist_file)
            except Exception as e:
                print("simulate worker error:", e)
            finally:
                if wordlist_file and os.path.exists(wordlist_file):
                    try:
                        os.remove(wordlist_file)
                    except Exception:
                        pass

        threading.Thread(target=worker, daemon=True).start()
        flash("simulation started", "info")
        return redirect(url_for("admin_dashboard"))
    return render_template("simulate_attack.html")

@app.route("/check_password", methods=["GET","POST"])
def check_password():
    result = None
    if request.method == "POST":
        pwd = request.form.get("password","")
        guesses, pattern = estimate_guesses(pwd)
        result = {"guesses": guesses, "pattern": pattern}
    return render_template("check_password.html", result=result)

# static route for uploads if needed (not used)
@app.route('/static/<path:filename>')
def static_files(filename):
    from flask import send_from_directory
    return send_from_directory('static', filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

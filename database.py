# database.py
import sqlite3
from datetime import datetime

DB = "pcdt.db"

def get_conn():
    conn = sqlite3.connect(DB, check_same_thread=False)
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()

    # Users (store sha512 hex)
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )""")

    # temporary plaintext storage (for PCFG analysis only)
    c.execute("""
    CREATE TABLE IF NOT EXISTS plaintext_temp (
        user_id INTEGER,
        password TEXT,
        created_at TEXT
    )""")

    # PCFG analysis
    c.execute("""
    CREATE TABLE IF NOT EXISTS pcfg_analysis (
        user_id INTEGER,
        guesses INTEGER,
        pattern TEXT,
        created_at TEXT
    )""")

    # JTR results (store audit_time in milliseconds)
    c.execute("""
    CREATE TABLE IF NOT EXISTS jtr_results (
        user_id INTEGER,
        guesses INTEGER,
        cracked INTEGER,
        cracked_password TEXT,
        audit_time INTEGER
    )""")

    # login attempts logs
    c.execute("""
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip TEXT,
        status TEXT,
        fingerprint TEXT,
        timestamp TEXT
    )""")

    # detection alerts
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT,
        details TEXT,
        timestamp TEXT
    )""")
    # config table for runtime settings
    c.execute("""
    CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )""")

    conn.commit()
    conn.close()

# user helpers
def insert_user(username, password_hash):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
    conn.commit()
    uid = c.lastrowid
    conn.close()
    return uid

def get_user_by_username(username):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row

def list_users():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, username FROM users")
    rows = c.fetchall()
    conn.close()
    return rows

# plaintext temp
def store_plaintext(user_id, password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO plaintext_temp (user_id, password, created_at) VALUES (?, ?, ?)",
              (user_id, password, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def delete_plaintext_for_user(user_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM plaintext_temp WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

# pcfg
def insert_pcfg(user_id, guesses, pattern):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO pcfg_analysis (user_id, guesses, pattern, created_at) VALUES (?, ?, ?, ?)",
              (user_id, guesses, pattern, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def fetch_pcfg_rows(limit=100):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT u.username, p.guesses, p.pattern, p.created_at FROM pcfg_analysis p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC LIMIT ?",
              (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# jtr
def insert_jtr_result(user_id, guesses, cracked, cracked_password, audit_time):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO jtr_results (user_id, guesses, cracked, cracked_password, audit_time) VALUES (?, ?, ?, ?, ?)",
              (user_id, guesses, cracked, cracked_password, audit_time))
    conn.commit()
    conn.close()

def fetch_jtr_rows(limit=100):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT u.username, j.guesses, j.cracked, j.cracked_password, j.audit_time FROM jtr_results j JOIN users u ON j.user_id = u.id ORDER BY j.audit_time DESC LIMIT ?",
              (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def clear_jtr_results():
    """Delete all rows from jtr_results table."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM jtr_results")
    conn.commit()
    conn.close()

# logs & alerts
def insert_login_log(username, ip, status, fingerprint):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO login_logs (username, ip, status, fingerprint, timestamp) VALUES (?, ?, ?, ?, ?)",
              (username, ip, status, fingerprint, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def fetch_recent_logs(limit=200):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username, ip, status, timestamp FROM login_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def insert_alert(alert_type, details):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO alerts (alert_type, details, timestamp) VALUES (?, ?, ?)",
              (alert_type, details, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def fetch_recent_alerts(limit=50):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT alert_type, details, timestamp FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_last_alert_time(alert_type, details):
    """Return the timestamp string of the most recent alert with same type and details, or None."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT timestamp FROM alerts WHERE alert_type=? AND details=? ORDER BY id DESC LIMIT 1", (alert_type, details))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def set_config(key, value):
    conn = get_conn()
    c = conn.cursor()
    c.execute("REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def get_config(key, default=None):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT value FROM config WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else default

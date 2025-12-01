# jtr_utils.py
import subprocess
import time
import hashlib
import os
from database import insert_jtr_result, get_conn, get_config, clear_jtr_results

# Configuration via environment variables
# Path to a preferred wordlist (set `JTR_WORDLIST`), default to common rockyou path
WORDLIST_PATH = os.environ.get("JTR_WORDLIST", "/usr/share/wordlists/rockyou.txt")
# Maximum time (seconds) to run John per user (set `JTR_MAX_SECONDS_PER_USER`)
MAX_SECONDS_PER_USER = int(os.environ.get("JTR_MAX_SECONDS_PER_USER", "30"))
# Maximum guesses to consider for non-wordlist fast-path (set `JTR_MAX_GUESSES`)
MAX_GUESSES = int(os.environ.get("JTR_MAX_GUESSES", "200000"))

def run_jtr_on_hash(user_id, stored_hexdigest):
    start = time.time()
    guesses = 0
    cracked = False
    cracked_password = None

    # Common passwords to try first (fast path)
    common_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
        'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
        'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321'
    ]
    
    # Try common passwords first
    for guess in common_passwords:
        guesses += 1
        ghex = hashlib.sha512(guess.encode()).hexdigest()
        if ghex == stored_hexdigest:
            cracked = True
            cracked_password = guess
            audit_time_ms = int((time.time() - start) * 1000)
            insert_jtr_result(user_id, guesses, 1 if cracked else 0, cracked_password, audit_time_ms)
            return guesses, cracked, cracked_password, str(audit_time_ms)
        if (time.time() - start) > MAX_SECONDS_PER_USER:
            audit_time_ms = int((time.time() - start) * 1000)
            insert_jtr_result(user_id, guesses, 0, None, audit_time_ms)
            return guesses, False, None, str(audit_time_ms)


    # Create a temporary file with the hash for John to consume
    import tempfile
    tf = None
    try:
        fd, tf = tempfile.mkstemp(prefix=f"jtrhash_{user_id}_", text=True)
        with os.fdopen(fd, 'w') as f:
            # John accepts raw hex hashes in the format user:hash
            f.write(f"user{user_id}:{stored_hexdigest}\n")

        # Determine wordlist: prefer DB config `JTR_WORDLIST`, then environment `WORDLIST_PATH`, then fallbacks
        wordlist = None
        db_wordlist = get_config('JTR_WORDLIST')
        if db_wordlist and os.path.exists(db_wordlist):
            wordlist = db_wordlist
        elif WORDLIST_PATH and os.path.exists(WORDLIST_PATH):
            wordlist = WORDLIST_PATH
        else:
            preferred_wordlists = [
                '/usr/share/wordlists/rockyou.txt',
                '/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt',
                '/usr/share/wordlists/fasttrack.txt'
            ]
            for p in preferred_wordlists:
                if os.path.exists(p):
                    wordlist = p
                    break

        # If we have a wordlist file available, do a fast Python-based dictionary attack
        # (the system's `john` may be an older build without Raw-SHA512 support).
        if wordlist:
            db_timeout = get_config('JTR_MAX_SECONDS_PER_USER')
            try:
                timeout = int(db_timeout) if db_timeout is not None else MAX_SECONDS_PER_USER
            except Exception:
                timeout = MAX_SECONDS_PER_USER

            try:
                with open(wordlist, 'r', errors='ignore') as wf:
                    for line in wf:
                        guess = line.rstrip('\n').rstrip('\r')
                        if not guess:
                            continue
                        guesses += 1
                        if hashlib.sha512(guess.encode()).hexdigest() == stored_hexdigest:
                            cracked = True
                            cracked_password = guess
                            break
                        if (time.time() - start) > timeout:
                            break
            except Exception:
                # If reading the wordlist fails, fall back to trying john if available
                wordlist = None

            if cracked or wordlist:
                audit_time_ms = int((time.time() - start) * 1000)
                insert_jtr_result(user_id, guesses, 1 if cracked else 0, cracked_password, audit_time_ms)
                return guesses, cracked, cracked_password, str(audit_time_ms)

        # Fallback: try invoking john (incremental) if no usable wordlist or Python path failed
        john_cmd = ["john", "--format=Raw-SHA512", "--incremental=All", tf]
        try:
            proc = subprocess.Popen(john_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            insert_jtr_result(user_id, guesses, 0, None, "john_missing")
            return guesses, False, None, "john_missing"

        # Determine timeout (DB config overrides environment/default)
        db_timeout = get_config('JTR_MAX_SECONDS_PER_USER')
        try:
            timeout = int(db_timeout) if db_timeout is not None else MAX_SECONDS_PER_USER
        except Exception:
            timeout = MAX_SECONDS_PER_USER

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass

        # Use john --show to see if it cracked the hash
        try:
            show = subprocess.run(["john", "--show", "--format=Raw-SHA512", tf], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            out = show.stdout or ''
            for line in out.splitlines():
                if ':' in line and not line.lower().startswith('loaded'):
                    parts = line.split(':')
                    if len(parts) >= 2 and parts[1].strip():
                        cracked_password = parts[1].strip()
                        cracked = True
                        break
        except Exception:
            pass

        audit_time_ms = int((time.time() - start) * 1000)
        insert_jtr_result(user_id, guesses, 1 if cracked else 0, cracked_password, audit_time_ms)
        return guesses, cracked, cracked_password, str(audit_time_ms)
    finally:
        try:
            if tf and os.path.exists(tf):
                os.remove(tf)
        except Exception:
            pass
def run_full_audit_all_users():
    # Clear previous audit results so table reflects only the latest run
    try:
        clear_jtr_results()
    except Exception:
        pass

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users")
    rows = c.fetchall()
    conn.close()
    results = []
    for user_id, stored_hash in rows:
        r = run_jtr_on_hash(user_id, stored_hash)
        results.append((user_id,) + r)
    return results

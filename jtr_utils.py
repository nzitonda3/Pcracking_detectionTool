# jtr_utils.py
import subprocess
import time
import bcrypt
import os
from database import insert_jtr_result

# parameters
MAX_SECONDS_PER_USER = 30
MAX_GUESSES = 200_000

def run_jtr_on_hash(user_id, stored_hash):
    """
    Uses john --incremental --stdout to stream guesses, hashes them with bcrypt and compares.
    Returns (guesses_counted, cracked_bool, cracked_password or None, audit_time_str)
    """
    start_time = time.time()
    guesses = 0
    cracked = False
    cracked_password = None

    # Try to spawn john --incremental --stdout
    try:
        proc = subprocess.Popen(["john", "--incremental=All", "--stdout"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except Exception as e:
        # If john not found or fails, return immediately
        return 0, False, None, "john_error"

    try:
        # stream guesses
        for line in proc.stdout:
            guess = line.rstrip("\n")
            guesses += 1

            # check password
            try:
                if bcrypt.checkpw(guess.encode(), stored_hash.encode()):
                    cracked = True
                    cracked_password = guess
                    break
            except Exception:
                # bcrypt check may throw for non-bcrypt hashes; ignore
                pass

            # time and guess limits
            if (time.time() - start_time) > MAX_SECONDS_PER_USER:
                break
            if guesses >= MAX_GUESSES:
                break
    except Exception as e:
        # streaming error
        pass
    finally:
        try:
            proc.kill()
        except Exception:
            pass

    audit_time = time.time() - start_time
    insert_jtr_result(user_id, guesses, 1 if cracked else 0, cracked_password, str(int(audit_time)))
    return guesses, cracked, cracked_password, str(int(audit_time))

def run_full_audit_all_users():
    from database import list_users, get_conn
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users")
    rows = c.fetchall()
    conn.close()

    results = []
    for user_id, stored_hash in rows:
        r = run_jtr_on_hash(user_id, stored_hash)
        results.append((user_id, ) + r)
    return results

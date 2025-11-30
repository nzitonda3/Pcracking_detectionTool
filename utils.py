# utils.py
import bcrypt
import hashlib
import os

# pepper (change in production)
PEPPER = os.environ.get("PWD_PEPPER", "lab_pepper_please_change")

def hash_password(plain):
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def fingerprint_password(plain):
    m = hashlib.sha256()
    m.update((PEPPER + plain).encode())
    return m.hexdigest()

# utils.py
import hashlib
import os

PEPPER = os.environ.get("PWD_PEPPER", "lab_pepper_change_me")

def hash_password_sha512(plain):
    h = hashlib.sha512()
    h.update(plain.encode())
    return h.hexdigest()

def verify_password_sha512(plain, hexdigest):
    return hash_password_sha512(plain) == hexdigest

def fingerprint_password(plain):
    # fingerprint for detection: SHA256(pepper + password)
    m = hashlib.sha256()
    m.update((PEPPER + (plain or "")).encode())
    return m.hexdigest()

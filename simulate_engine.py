# simulate_engine.py
import requests
import time
import os

def _post_attempt(url, username, password, ip):
    headers = {"X-Forwarded-For": ip}
    try:
        requests.post(url, data={"username": username, "password": password}, headers=headers, timeout=3)
    except Exception:
        pass

def simulate(attack_type, usernames, passwords, ip, count, wordlist_path=None):
    """
    attack_type: 'bruteforce' | 'stuffing' | 'spray'
    usernames: list
    passwords: list
    ip: source ip
    count: attempts per password/user
    wordlist_path: optional path to file with passwords (one per line)
    """
    url = "http://127.0.0.1:5000/login"

    # if wordlist provided, read it and override passwords
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                passwords = [l.strip() for l in f if l.strip()]
        except Exception:
            passwords = passwords or []

    if attack_type == "bruteforce":
        if not usernames:
            return
        target = usernames[0]
        for pwd in passwords:
            for _ in range(count):
                _post_attempt(url, target, pwd, ip)

    elif attack_type == "stuffing":
        if not passwords:
            return
        same_pwd = passwords[0]
        for user in usernames:
            for _ in range(count):
                _post_attempt(url, user, same_pwd, ip)

    elif attack_type == "spray":
        if not passwords:
            return
        pwd = passwords[0]
        for user in usernames:
            _post_attempt(url, user, pwd, ip)
            time.sleep(1)

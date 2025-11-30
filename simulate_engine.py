# simulate_engine.py
import requests
import time

def simulate(attack_type, usernames, passwords, ip, count):
    """
    attack_type: 'bruteforce' | 'stuffing' | 'spray'
    usernames: list of usernames (strings)
    passwords: list of passwords (strings)
    ip: source IP to simulate (string)
    count: attempts per iteration (int)
    """
    url = "http://127.0.0.1:5000/login"
    headers = {"X-Forwarded-For": ip}

    if attack_type == "bruteforce":
        target = usernames[0] if usernames else usernames
        for pwd in passwords:
            for _ in range(count):
                try:
                    requests.post(url, data={"username": target, "password": pwd}, headers=headers, timeout=3)
                except Exception:
                    pass

    elif attack_type == "stuffing":
        same_pwd = passwords[0] if passwords else ""
        for user in usernames:
            for _ in range(count):
                try:
                    requests.post(url, data={"username": user, "password": same_pwd}, headers=headers, timeout=3)
                except Exception:
                    pass

    elif attack_type == "spray":
        pwd = passwords[0] if passwords else ""
        for user in usernames:
            try:
                requests.post(url, data={"username": user, "password": pwd}, headers=headers, timeout=3)
            except Exception:
                pass
            time.sleep(1)

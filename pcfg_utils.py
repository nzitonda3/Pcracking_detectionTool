from database import insert_pcfg
from datetime import datetime

def identify_pattern_and_groups(password):
    groups = []
    cur = None
    cnt = 0
    for ch in password:
        cls = 'L' if ch.islower() else ('U' if ch.isupper() else ('D' if ch.isdigit() else 'S'))
        if cls == cur:
            cnt += 1
        else:
            if cur is not None:
                groups.append((cur, cnt))
            cur = cls
            cnt = 1
    if cur is not None:
        groups.append((cur, cnt))
    pattern = ''.join([f"{g[0]}{g[1]}" for g in groups])
    return pattern, groups

def estimate_guesses(password):
    """Estimate guesses needed to crack password using common wordlist ranking.
    
    This uses a realistic approach: if password is in common wordlist, rank it low.
    Otherwise, estimate based on character composition complexity.
    """
    pattern, groups = identify_pattern_and_groups(password)
    
    # Common passwords and their estimated rank in typical wordlists
    COMMON_PASSWORDS = {
        'password': 1,
        '123456': 2,
        '12345678': 3,
        'qwerty': 4,
        'abc123': 5,
        'monkey': 6,
        '1234567': 7,
        'letmein': 8,
        'trustno1': 9,
        'dragon': 10,
    }
    
    pwd_lower = password.lower()
    if pwd_lower in COMMON_PASSWORDS:
        return COMMON_PASSWORDS[pwd_lower], pattern
    
    # For uncommon passwords, estimate based on pattern complexity
    # Length multiplier
    length_score = len(password) * 50
    
    # Complexity bonus
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    complexity = sum([has_lower, has_upper, has_digit, has_symbol])
    complexity_score = 100 * (complexity ** 2)  # Non-linear increase
    
    guesses = length_score + complexity_score
    return max(guesses, 100), pattern

def analyze_and_store(user_id, password):
    guesses, pattern = estimate_guesses(password)
    insert_pcfg(user_id, guesses, pattern)
    return guesses, pattern

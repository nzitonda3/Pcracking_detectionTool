# pcfg_utils.py
import re
from math import log10
from database import insert_pcfg
from datetime import datetime

# simple probabilities chosen for demonstration (tweakable)
PROB_LOWER = 0.09
PROB_UPPER = 0.06
PROB_DIGIT = 0.10
PROB_SYMBOL = 0.02

def identify_pattern(password):
    pattern = ""
    groups = []
    # collapse consecutive identical classes into counts, e.g. U2L4D2 -> (U,2),(L,4),(D,2)
    cur = None
    count = 0
    for ch in password:
        cls = 'L' if ch.islower() else ('U' if ch.isupper() else ('D' if ch.isdigit() else 'S'))
        if cls == cur:
            count += 1
        else:
            if cur is not None:
                groups.append((cur, count))
            cur = cls
            count = 1
    if cur is not None:
        groups.append((cur, count))

    # build pattern string
    pattern = ''.join([f"{g[0]}{g[1]}" for g in groups])
    return pattern, groups

def estimate_guesses(password):
    # simple model: multiply probabilities per character class
    pattern, groups = identify_pattern(password)
    prob = 1.0
    for cls, cnt in groups:
        if cls == 'L':
            prob *= (PROB_LOWER ** cnt)
        elif cls == 'U':
            prob *= (PROB_UPPER ** cnt)
        elif cls == 'D':
            prob *= (PROB_DIGIT ** cnt)
        else:
            prob *= (PROB_SYMBOL ** cnt)

    # crude conversion to guesses:
    if prob <= 0:
        guesses = 10**6
    else:
        guesses = int(1.0 / prob)
    return guesses, pattern

def analyze_and_store(user_id, password):
    guesses, pattern = estimate_guesses(password)
    insert_pcfg(user_id, guesses, pattern)
    return guesses, pattern

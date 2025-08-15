#!/usr/bin/env python3
import requests
import hashlib
import re
from math import log2

def check_breaches(password):
    """Check if password exists in known breaches using Have I Been Pwned API."""
    # Hash the password (SHA-1)
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        # Fetch hash suffixes from HIBP
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        response.raise_for_status()
        
        # Check if our suffix exists in the results
        for line in response.text.splitlines():
            if suffix in line:
                breaches = int(line.split(":")[1])
                print(f"⚠️ This password appears in {breaches} known breaches!")
                return True
        print("✅ No known breaches found for this password.")
        return False
    except Exception as e:
        print(f"❌ API Error: {e}")
        return False

def calculate_entropy(password):
    """Calculate password entropy (bits of security)."""
    char_pool = 0
    if re.search(r'[a-z]', password): char_pool += 26
    if re.search(r'[A-Z]', password): char_pool += 26
    if re.search(r'[0-9]', password): char_pool += 10
    if re.search(r'[^a-zA-Z0-9]', password): char_pool += 32  # Special chars
    
    entropy = len(password) * log2(char_pool) if char_pool else 0
    return entropy

def analyze_strength(password):
    """Comprehensive password analysis."""
    # Length check
    if len(password) < 8:
        print("❌ Too short (min 8 characters)")
    elif len(password) >= 12:
        print("✅ Length: Strong")
    else:
        print("⚠️ Length: Moderate")
    
    # Complexity check
    checks = {
        "Lowercase": r'[a-z]',
        "Uppercase": r'[A-Z]',
        "Digits": r'[0-9]',
        "Special": r'[^a-zA-Z0-9]'
    }
    for name, pattern in checks.items():
        if not re.search(pattern, password):
            print(f"⚠️ Missing: {name}")
    
    # Entropy evaluation
    entropy = calculate_entropy(password)
    if entropy > 80:
        print(f"🔒 Entropy: Excellent (~{int(entropy)} bits)")
    elif entropy > 60:
        print(f"🔐 Entropy: Good (~{int(entropy)} bits)")
    else:
        print(f"⚠️ Entropy: Weak (~{int(entropy)} bits)")

if __name__ == "__main__":
    print("🔑 Password Strength Checker")
    password = input("Enter password to analyze: ")
    print("\n--- Analysis Report ---")
    analyze_strength(password)
    print("\n--- Breach Check ---")
    check_breaches(password)

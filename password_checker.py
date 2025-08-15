"""
Password Strength & Breach Checker
Author: Zairy Izzul Aslam
Last Updated: 2025-08-15

Description:
    Evaluates a password against common strength criteria and 
    checks its presence in known data breaches using the 
    Have I Been Pwned (HIBP) API without transmitting the 
    full password.
"""

import getpass
import re
import hashlib
import requests

# Introductory message for the user
print(
    "This tool checks your password’s strength locally and verifies "
    "if it appears in known data breaches (without sending the full password)."
)

# Prompt for password (input hidden)
password = getpass.getpass("Enter Password To Check Strength: ")

# List to collect any strength issues found
strength_issues = []

# Password policy checks
if len(password) < 12:
    strength_issues.append("Password should be at least 12 characters long.")
if not re.search(r"[A-Z]", password):
    strength_issues.append("Password should contain at least one uppercase letter.")
if not re.search(r"[a-z]", password):
    strength_issues.append("Password should contain at least one lowercase letter.")
if not re.search(r"\d", password):
    strength_issues.append("Password should contain at least one number.")
if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
    strength_issues.append("Password should contain at least one special symbol.")

# Prepare SHA-1 hash of the password for HIBP k-Anonymity API
sha1pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
prefix = sha1pwd[:5]
suffix = sha1pwd[5:]

# Query the HIBP API with only the hash prefix
url = f"https://api.pwnedpasswords.com/range/{prefix}"
response = requests.get(url)

breach_count = 0
if response.status_code == 200:
    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            breach_count = int(count)
            break
else:
    print("\n⚠️ Unable to check Have I Been Pwned API.")

# Strength check results
if strength_issues:
    print("\nWeaknesses found:")
    for issue in strength_issues:
        print("-", issue)
else:
    print("\nYour password meets common strength requirements.")

# Breach check results
if breach_count > 0:
    print(f"⚠️ WARNING: This password has appeared in {breach_count:,} breaches!")
else:
    print("✅ This password has not been found in known breaches.")

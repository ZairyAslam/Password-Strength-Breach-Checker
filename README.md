# Password Strength & Breach Checker 🔐

A Python command-line tool that evaluates password strength against common security best practices **and** checks if the password has appeared in known data breaches using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3) API — without transmitting the full password.

## ✨ Features
- **Password Strength Check** — Validates length, uppercase, lowercase, numbers, and special characters.
- **Breach Detection** — Uses the HIBP k-Anonymity API model to check if the password exists in public breach databases without revealing the full password.
- **Privacy-First** — Your actual password is never sent over the internet.
- **Simple CLI Interface** — Runs directly in your terminal.

## 📦 Requirements
- Python 3.6+
- `requests` library

Install dependencies with:
```bash
pip install requests

# 🔑 Password Strength Checker

A Python tool to analyze password strength by checking:
- Length & complexity
- Entropy (cracking difficulty)
- Known data breaches (via Have I Been Pwned API)


## 🛠️ Features
- **Breach Check**: Uses [HIBP API](https://haveibeenpwned.com/API/v3) to detect compromised passwords.
- **Entropy Calculation**: Estimates password strength in bits.
- **Complexity Analysis**: Checks for uppercase, digits, and special chars.

## ⚙️ Installation
1. Clone the repo:
   ```bash
   git clone https://github.com/siddhanth36/password-checker.git
   cd password-checker
   # Install dependencies
    pip install requests

    # Usage
    python3 password_checker.py

   # Enter a password to analyze.


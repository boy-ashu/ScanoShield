import secrets
import string
import re
import os
import sys
import math
import hashlib
import urllib.request
import django
from django.contrib.auth.hashers import make_password

class ProfessionalPasswordToolkit:
    """
    Advanced security toolkit for password strength analysis,
    one-way hashing, and secure data-breach leak checking.
    """

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculates password entropy in bits."""
        if not password:
            return 0.0
        pool_size = 0
        if re.search(r"[a-z]", password): pool_size += 26
        if re.search(r"[A-Z]", password): pool_size += 26
        if re.search(r"\d", password): pool_size += 10
        if re.search(r"[ !@#$%^&*(),.?\":{}|<>_+-]", password): pool_size += 32
        if pool_size == 0: return 0.0
        return round(len(password) * math.log2(pool_size), 2)

    @staticmethod
    def check_strength(password: str) -> dict:
        """Evaluates password strength and provides simple feedback."""
        feedback = []
        common_passwords = ["123456", "password", "qwerty", "password123", "admin123", "welcome"]
        
        if password.lower() in common_passwords:
            return {
                "score": 0,
                "status": "CRITICAL RISK 🚨",
                "suggestions": ["This password is blacklisted. Change it immediately!"]
            }

        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[ !@#$%^&*(),.?\":{}|<>_+-]", password))
        length = len(password)

        if length < 8:
            feedback.append("Make it longer (at least 8 characters).")
        if not (has_upper and has_lower):
            feedback.append("Use both BIG (ABC) and small (abc) letters.")
        if not has_digit:
            feedback.append("Add at least one number (0-9).")
        if not has_special:
            feedback.append("Add a special character (like @, #, $, %).")

        entropy = ProfessionalPasswordToolkit.calculate_entropy(password)
        if length < 8 or entropy < 30:
            score, status = 1, "WEAK ⚠️"
        elif entropy < 50:
            score, status = 2, "FAIR 😐"
        elif entropy < 70:
            score, status = 3, "GOOD 🙂"
        else:
            score, status = 4, "STRONG 💪"

        if not feedback and score < 3:
            score, status = 3, "GOOD 🙂"

        return {
            "score": score,
            "status": status,
            "suggestions": feedback if feedback else ["Your password structure is safe and secure!"]
        }

    @staticmethod
    def check_leak(password: str) -> dict:
        """
        Checks if the password has been leaked in data breaches using HIBP API.
        Uses K-Anonymity to protect user privacy.
        """
        # 1. SHA-1 Hash निकालें
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5, tail = sha1_hash[:5], sha1_hash[5:]
        
        # 2. सिर्फ शुरुआती 5 अक्षर API को भेजें
        url = f"https://api.pwnedpasswords.com/range/{first5}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'ScanoShield-Auditor'})
            with urllib.request.urlopen(req) as response:
                hashes = response.read().decode('utf-8').splitlines()
            
            # 3. चेक करें कि बाकी का हैश लिस्ट में मौजूद है या नहीं
            for h in hashes:
                leak_hash, leak_count = h.split(':')
                if leak_hash == tail:
                    return {
                        "is_leaked": True,
                        "count": int(leak_count),
                        "status": "⚠️ LEAKED / STOLEN ⚠️"
                    }
            
            return {
                "is_leaked": False,
                "count": 0,
                "status": "✅ CLEAN / SAFE ✅"
            }
        except Exception as e:
            return {
                "is_leaked": False,
                "count": 0,
                "status": f"❌ Unable to connect to leak database ({str(e)})"
            }

    @staticmethod
    def hash_password(password: str) -> str:
        """Hashes plain text via Django's PBKDF2 layers."""
        return make_password(password)

    @staticmethod
    def generate_secure_password(length: int = 14) -> str:
        """Generates a high-entropy cryptographically secure random password."""
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
        while True:
            pwd = ''.join(secrets.choice(all_chars) for _ in range(length))
            if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) and 
                any(c.isdigit() for c in pwd) and any(c in "!@#$%^&*()_+-=" for c in pwd)):
                return pwd


# ==============================================================================
#                      SIMPLE WORDS USER MENU INTERFACE
# ==============================================================================
if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.append(project_root)

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ScanoShield.settings")
    try: django.setup()
    except Exception: pass

    print("\n" + "="*50)
    print("             SCANOSHIELD PASSWORD TOOL            ")
    print("="*50)
    print("  1. Check Password Strength (मजबूती की जांच)")
    print("  2. Check Password Leak/Theft (चोरी की जांच)")
    print("="*50)
    
    choice = input("Select an option (1 or 2): ").strip()
    print("-" * 50)

    if choice in ['1', '2']:
        user_password = input("Type your password: ").strip()
        print("-" * 50)

        if choice == '1':
            # STRENGTH OPERATIONS
            analysis = ProfessionalPasswordToolkit.check_strength(user_password)
            print(f"🔒 Password Status : {analysis['status']}")
            print(f"⭐ Safety Score   : {analysis['score']} out of 4")
            print("-" * 50)
            print("💡 How to make it better:")
            for index, msg in enumerate(analysis['suggestions'], 1):
                print(f"  {index}. {msg}")

        elif choice == '2':
            # LEAK / THEFT OPERATIONS
            print("Searching international database for data leaks...\n")
            leak_analysis = ProfessionalPasswordToolkit.check_leak(user_password)
            print(f"🚨 Theft Status : {leak_analysis['status']}")
            
            if leak_analysis['is_leaked']:
                print(f"❌ DANGER: This password has been leaked {leak_analysis['count']} times in past data breaches!")
                print("👉 Change this password immediately. It is known to hackers.")
            else:
                print("🎉 GREAT NEWS: This password was never found in any known leaks.")

        # Background Django Hashing (Simulation)
        try: _ = ProfessionalPasswordToolkit.hash_password(user_password)
        except Exception: pass

        print("-" * 50)
        recommended = ProfessionalPasswordToolkit.generate_secure_password(14)
        print(f"🎁 Safe password suggestion for you:\n   👉 {recommended}")
        print("="*50 + "\n")
    else:
        print("Invalid Selection! Run the script again.")
        print("="*50 + "\n")

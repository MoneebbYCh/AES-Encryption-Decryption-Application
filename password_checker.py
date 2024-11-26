import re
import random
import string


def check_password_strength(password):
    # Criteria for checking the password strength
    length_criteria = len(password) >= 8
    lowercase_criteria = re.search(r"[a-z]", password) is not None
    uppercase_criteria = re.search(r"[A-Z]", password) is not None
    digit_criteria = re.search(r"[0-9]", password) is not None
    special_character_criteria = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None

    # Count the number of met criteria
    criteria_met = sum([length_criteria, lowercase_criteria, uppercase_criteria, digit_criteria, special_character_criteria])

    # Determine strength based on the number of met criteria
    if criteria_met == 5:
        return "Strong"
    elif criteria_met >= 3:
        return "Medium"
    else:
        return "Weak"

# Password Suggestion 
def suggest_password():
    length = 12
    password_characters = (
        random.choices(string.ascii_lowercase, k=3) +
        random.choices(string.ascii_uppercase, k=3) +
        random.choices(string.digits, k=3) +
        random.choices("!@#$%^&*()", k=3)
    )
    password_characters += random.choices(string.ascii_letters + string.digits + "!@#$%^&*()", k=length - len(password_characters))
    random.shuffle(password_characters)
    return ''.join(password_characters)

# Real-time checklist 
def get_checklist(password):
    return [
        ("At least 8 characters", len(password) >= 8),
        ("Contains a lowercase letter", bool(re.search(r"[a-z]", password))),
        ("Contains an uppercase letter", bool(re.search(r"[A-Z]", password))),
        ("Contains a digit", bool(re.search(r"[0-9]", password))),
        ("Contains a special character", bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)))
    ]

import sqlite3
from hashlib import sha256
import os

def initialize_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)''')
    conn.commit()
    conn.close()

def hash_password(password):
    return sha256(password.encode()).hexdigest()

def create_user_file(username):
    """Creates a user-specific file for storing their keys."""
    file_path = f'keys_{username}.txt'
    if not os.path.exists(file_path):  # Only create the file if it doesn't exist
        with open(file_path, 'w') as file:
            pass  # Create an empty file

def register_user(username, password):
    password_hash = hash_password(password)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        # Insert the new user into the database
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()

        # Create the user-specific file for storing their keys
        create_user_file(username)

        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()

def update_password(username, new_password):
    password_hash = hash_password(new_password)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
    conn.commit()
    conn.close()
    return True

def authenticate_user(username, password):
    password_hash = hash_password(password)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None and result[0] == password_hash

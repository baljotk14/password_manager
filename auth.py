# auth.py
import json
import bcrypt
import getpass
from storage import load_users, save_users

USERS_FILE = "data/users.json"

def register_user():
    users = load_users(USERS_FILE)

    username = input("Choose a username: ").strip()
    if username in users:
        print("⚠️  That username is already taken.")
        return False

    # hide password as it’s typed
    password = getpass.getpass("Choose a master password: ")
    # hash it
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users[username] = hashed
    save_users(USERS_FILE, users)
    print("✅  Registration successful!")
    return True

def verify_user():
    users = load_users(USERS_FILE)

    username = input("Username: ").strip()
    if username not in users:
        print("❌  No such user.")
        return None

    password = getpass.getpass("Master password: ").encode()
    hashed = users[username].encode()

    if bcrypt.checkpw(password, hashed):
        print("🔓  Login successful!")
        return username
    else:
        print("❌  Incorrect password.")
        return None

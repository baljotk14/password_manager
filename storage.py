# storage.py
import json
import os

def load_users(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def save_users(path, users_dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(users_dict, f, indent=2)

def load_vault(username):
    vault_path = f"data/vaults/{username}.json"
    if not os.path.exists(vault_path):
        return []
    with open(vault_path, "r") as f:
        return json.load(f)

def save_vault(username, entries):
    vault_path = f"data/vaults/{username}.json"
    os.makedirs(os.path.dirname(vault_path), exist_ok=True)
    with open(vault_path, "w") as f:
        json.dump(entries, f, indent=2)

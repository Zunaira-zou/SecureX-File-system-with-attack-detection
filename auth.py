import json
import os
import time
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize Argon2 hasher
ph = PasswordHasher()

# File paths that will generate automatically
USERS_FILE = 'users.json'
ATTACK_LOG = 'attack_logs.txt'

def log_attack(username, reason):
    #Log attack attempts
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(ATTACK_LOG, 'a') as f:
        f.write(f"[{timestamp}] User: {username} | Reason: {reason}\n")
    print(f"\n  ATTACK DETECTED: {reason}")

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def register_user():
    users = load_users()
    username = input("Enter new username: ").strip()
    
    if username in users:
        print("Username already exists!")
        return False
    
    password = input("Enter strong password: ").strip()
    if len(password) < 8:
        print("Password must be at least 8 characters!")
        return False
    
    # Hash password with Argon2
    hashed_password = ph.hash(password)
    
    users[username] = {
        "password_hash": hashed_password,
        "failed_attempts": 0,
        "lock_until": 0
    }
    
    save_users(users)
    print(f"User '{username}' registered successfully!")
    return True

def login_user():
    users = load_users()
    username = input("Enter username: ").strip()
    
    if username not in users:
        print("Invalid username!")
        log_attack(username, "Invalid username attempt")
        return None
    
    user = users[username]
    current_time = time.time()
    
    # Check if account is locked
    if user["lock_until"] > current_time:
        remaining = int(user["lock_until"] - current_time)
        print(f"Account locked! Try again in {remaining} seconds.")
        log_attack(username, f"Login attempt on locked account")
        return None
    
    password = input("Enter password: ").strip()
    
    try:
        ph.verify(user["password_hash"], password)
        
        # On success → resets failed attempts.
        user["failed_attempts"] = 0
        user["lock_until"] = 0
        save_users(users)
        
        print(f"Login successful! Welcome, {username}")
        return username
        
    except VerifyMismatchError:
        # On failure → increments failed attempts.
        user["failed_attempts"] += 1
        save_users(users)
        
        if user["failed_attempts"] >= 5:
            user["lock_until"] = current_time + 300  # Lock for 5 minutes (300 seconds)
            save_users(users)
            print("Too many failed attempts! Account locked for 5 minutes.")
            log_attack(username, "Brute force attempt - Account locked")
        else:
            remaining = 5 - user["failed_attempts"]
            print(f"Wrong password! {remaining} attempts left.")
            log_attack(username, f"Wrong password attempt ({user['failed_attempts']}/5)")
        
        return None

# For testing auth file independently
if __name__ == "__main__":
    while True:
        print("\n=== Authentication Module ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter choice: ")
        
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            break
        else:
            print("Invalid choice!")
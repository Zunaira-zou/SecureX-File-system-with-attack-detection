# SecureX-File-system-with-attack-detection
SecureX is a secure file storage system with multi-layered protection including Argon2 hashing, AES-256 encryption, HMAC integrity verification, and intelligent brute-force attack detection.
# Features
- User registration and login with Argon2 password hashing
- Multi-layer security:
  - Layer 1: Authentication + session
  - Layer 2: AES-256-CBC encryption
  - Layer 3: HMAC-SHA256 integrity verification
- Brute force attack detection (account lock after 5 failed attempts)
- File tampering detection
- Secure file upload, download and delete
# How to Run
1. Install dependencies:
   pip install cryptography argon2-cffi
   pip install customtinkter
2. Run:
   python main.py
   python securex_gui.py

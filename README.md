# SecureX — Multi-Layer Secure File System with Attack Detection

SecureX is an educational, proof-of-concept secure file storage system that demonstrates multi-layered protection techniques for user authentication, file confidentiality, and integrity/attack detection. It combines Argon2 password hashing, AES-256 file encryption, HMAC integrity checks, and simple brute-force detection and logging. SecureX is intended for learning, prototyping, or as a foundation for a production-grade system after applying recommended hardening.

Highlights
- Argon2 for secure password hashing (resistant to GPU cracking).
- PBKDF2-derived AES-256 symmetric keys for file encryption.
- AES-256-CBC for confidentiality + HMAC-SHA256 for integrity/authenticity.
- Account lockout and attempt counters to mitigate brute-force attacks.
- Simple GUI using CustomTkinter and a CLI for quick testing.
- Attack logging to record suspicious activities.

Features
- User registration and authentication with Argon2 hashed passwords.
- Per-file encryption with:
  - PBKDF2(HMAC-SHA256) key derivation with per-file salt,
  - AES-256-CBC encryption,
  - HMAC-SHA256 over (salt || IV || ciphertext) to detect tampering.
- Simple file management: upload (encrypt), list, download (decrypt), and delete.
- Brute-force mitigation: per-user failed attempt counters, account lockout (configurable), and attack logging.
- GUI: a cross-platform desktop UI using CustomTkinter for a friendly experience.
- CLI: a terminal interface suitable for automation or lightweight use.

Security Model & Design Notes
- Passwords are hashed using Argon2 (via argon2-cffi), which provides strong resistance to offline cracking.
- File encryption keys are derived via PBKDF2-HMAC(SHA256) from the user-provided password plus a random salt. Salt is stored alongside ciphertext in the .enc file.
- Integrity is enforced by HMAC-SHA256. If the HMAC verification fails, decryption is refused and an "attack detected" condition is logged/shown.
- The system stores encrypted files in the `storage/` directory. Minimal metadata is stored in `users.json` (user records).
- Attack events are recorded in `attack_logs.txt`.

Requirements
- Python 3.8+
- Recommended packages:
  - cryptography
  - argon2-cffi
  - customtkinter (GUI only)
- Example pip install:
  pip install cryptography argon2-cffi customtkinter

Installation
1. Clone the repository:
   git clone https://github.com/<your-username>/SecureX-File-system-with-attack-detection.git
   cd SecureX-File-system-with-attack-detection

2. Create a virtual environment (recommended):
   python -m venv .venv
   source .venv/bin/activate  # macOS / Linux
   .venv\Scripts\activate     # Windows

3. Install dependencies:
   pip install cryptography argon2-cffi customtkinter

Running SecureX

CLI Mode
- Launch the terminal interface:
  python main.py
- Follow prompts to Register → Login → Use file operations (Upload, List, Download, Delete).

GUI Mode
- Launch the GUI:
  python securex_gui.py
- Use the provided graphical controls to register, login, upload, list, download, delete files, and view attack logs.

File Layout
- main.py — CLI entrypoint. Presents a simple menu for registration, login, and file operations.
- securex_gui.py — CustomTkinter-based GUI application.
- auth.py — User registration/login, Argon2 password hashing, brute-force detection, and attack logging.
- encryption.py — Key derivation, AES-256-CBC encryption/decryption, HMAC integrity checks.
- file_manager.py — CLI file-management helpers (wraps encryption functions).
- storage/ — Directory where encrypted files (.enc) and decrypted output are stored (created at runtime).
- users.json — Per-user data (created at runtime).
- attack_logs.txt — Audit trail for suspicious activity and lockouts (created at runtime).

Usage Examples

Register (CLI)
1. Run: python main.py
2. Choose "Register", enter username and a strong password (≥ 8 chars).

Login (CLI)
1. Run: python main.py
2. Choose "Login" and provide credentials.
3. You will be prompted to re-enter the password for file operations (this is how the current implementation derives keys).

Encrypt a file (CLI)
- After login, choose "Upload and Encrypt File" and provide the full path to the file you want to secure. The encrypted file will be saved to `storage/<filename>.enc`.

Decrypt a file (CLI)
- Choose "Download and Decrypt File", then choose the file by number. If HMAC verification passes and the correct password is provided, a decrypted copy will be saved in `storage/decrypted_<originalname>`.

Attack/Lockout Behavior
- After 5 incorrect passwords for a user, the account is locked for 5 minutes by default. Events are appended to `attack_logs.txt`.

Limitations & Security Considerations
- This project is a demonstration — not production-ready. Important considerations before production use:
  - AES-CBC+HMAC is secure when used correctly, but using an authenticated encryption mode (e.g., AES-GCM) is simpler and less error-prone.
  - Password-derived keys are generated from the user password at runtime; the application currently requires entering the password to decrypt files. There is no secure long-term key storage (KMS/HSM).
  - The GUI stores the plaintext password in memory while the session is active — consider zeroing memory or using OS-provided secure credential stores.
  - The users.json and attack_logs.txt files are simple JSON / text files and should be protected by filesystem permissions and/or moved to a secure backend.
  - No multi-user isolation currently; all encrypted files are stored in a single `storage/` directory visible to any local user who can read it.
  - No TLS/Network encryption is implemented — the app is local-only.

Recommended Improvements
- Replace PBKDF2 + HMAC with an AEAD cipher like AES-GCM or ChaCha20-Poly1305 (authenticated encryption).
- Use Argon2 for file key derivation or HKDF with a secure server-side secret.
- Introduce per-user storage directories and per-file metadata (owner, created_at).
- Integrate a secure key management solution (KMS) for production deployments.
- Avoid re-prompting users for plaintext passwords: consider session tokens or OS credential storage.
- Harden filesystem permissions for `users.json`, `attack_logs.txt`, and `storage/`.
- Add unit/integration tests and continuous integration (GitHub Actions).
- Provide a well-documented configuration file (timeout durations, iteration counts, storage path).
- Add input validation (file names, path traversal protection) and safe handling of large files (streaming encryption).

Troubleshooting
- "ModuleNotFoundError" — ensure required packages are installed in the active virtualenv.
- GUI fails to start — ensure `customtkinter` is installed and compatible with your Python/Tk version.
- Decryption fails with "File integrity check FAILED" — either the wrong password was supplied, or the encrypted file was tampered with/corrupted.

Contributing
Contributions, issues, and feature requests are welcome. Please:
1. Open an issue describing the bug or feature.
2. Fork the repository and create a feature branch.
3. Submit a pull request with clear notes and tests where appropriate.

License
- This project is licensed under MIT License.

Contact
- Author: Zunaira-zou
- GitHub: https://github.com/Zunaira-zou/SecureX-File-system-with-attack-detection

Disclaimer
This project is provided "as-is" for educational and prototyping purposes. It is not intended for protecting sensitive production data without additional hardening and security reviews.

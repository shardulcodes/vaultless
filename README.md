# Deterministic Password Generator

A secure, zero-storage password manager built using Flask.  
It deterministically generates strong passwords based on a combination of a master password, site/service name, and a device-specific secret — without storing any actual passwords.

---

## Features

- **Zero Storage** – No passwords are stored anywhere.
- **Device-bound Secrets** – Passwords are tied to the specific machine.
- **Deterministic Generation** – Same input → same output every time.
- **PBKDF2 + HMAC Security** – Strong hashing and keyed hashing protect inputs.
- **Rate Limiting** – Prevents brute-force or abuse with `Flask-Limiter`.
- **HTTPS Security Headers** – Enforced via `Flask-Talisman`.
- **Input Validation** – Ensures only proper inputs are accepted.

---

## Tech Stack

- **Backend**: Python 3, Flask
- **Crypto**: `cryptography`, `hashlib`, `hmac`
- **Security**: `Flask-Talisman`, `Flask-Limiter`
- **Rate Limiting**: IP-based with configurable limits

---

## How It Works

1. On first run, the app creates:
   - `secret.key`: a unique device secret
   - `master.key`: reserved for potential encryption features
2. When a user inputs:
   - `name` (e.g., "Gmail")
   - `master_password` (your secure phrase)
   - `length` (password length: 8–64)
3. A **PBKDF2-derived key** is generated from the inputs + device secret.
4. This key is used in an **HMAC-SHA256** hash to derive a secure password.

---

## 🛠️ Installation & Usage

### Step 1: Clone the repository

```bash
git clone https://github.com/yourusername/zero-storage-password-generator.git
cd zero-storage-password-generator

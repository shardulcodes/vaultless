from flask import Flask, render_template, request, jsonify
import os
import base64
import hashlib
import string
import hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, content_security_policy=None)  # Enforce HTTPS

# ========= Rate Limiting =========
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

# ========= Key Files =========
DEVICE_SECRET_FILE = "device_secret.key"
FERNET_KEY_FILE = "fernet_master.key"

def get_or_create_secret(filename, length=64):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return f.read()
    else:
        secret = base64.urlsafe_b64encode(os.urandom(length))
        with open(filename, 'wb') as f:
            f.write(secret)
        return secret

DEVICE_SECRET = get_or_create_secret(DEVICE_SECRET_FILE)
FERNET_KEY = get_or_create_secret(FERNET_KEY_FILE)

# ========= Password Generator =========
def generate_password(name: str, master_password: str, length: int) -> str:
    if length < 8 or length > 64:
        return None

    combined = f"{DEVICE_SECRET.decode()}{name}{master_password}{length}".encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=DEVICE_SECRET,
        iterations=100000,
    )
    key = kdf.derive(combined)

    hash_digest = hmac.new(key, combined, hashlib.sha256).hexdigest()

    charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    password = ''.join(charset[int(hash_digest[i * 2:(i * 2) + 2], 16) % len(charset)] for i in range(length))

    return password

# ========= Routes =========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
@limiter.limit("5 per minute")
def generate():
    data = request.json

    if not data or "name" not in data or "master_password" not in data or "length" not in data:
        return jsonify({"error": "Invalid request format"}), 400

    try:
        length = int(data["length"])
    except ValueError:
        return jsonify({"error": "Length must be an integer"}), 400

    if length < 8 or length > 64:
        return jsonify({"error": "Password length must be between 8 and 64."}), 400

    password = generate_password(data["name"], data["master_password"], length)
    return jsonify({"password": password})

if __name__ == '__main__':
    app.run(debug=True)

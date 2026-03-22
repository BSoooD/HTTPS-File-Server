import os
import http.server
import ssl
import base64
import time
import hmac
import subprocess
from pathlib import Path
from getpass import getpass
from datetime import datetime, timedelta, timezone
import argparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# ---------------- Command-line arguments ----------------
parser = argparse.ArgumentParser(description="HTTPS file server with optional Cloudflare Tunnel")
parser.add_argument("--port", type=int, default=8443, help="Port to run HTTPS server on")
parser.add_argument("--cloudflare", action="store_true", help="Enable Cloudflare Tunnel")
parser.add_argument("--dir", type=str, default=os.getcwd(), help="Directory to serve")
args = parser.parse_args()

PORT = args.port
ENABLE_CLOUDFLARE = args.cloudflare
SERVE_DIR = Path(args.dir).resolve()

if not SERVE_DIR.exists() or not SERVE_DIR.is_dir():
    print(f"Directory {SERVE_DIR} does not exist. Exiting.")
    exit(1)

print(f"Serving directory: {SERVE_DIR}")

USERNAME = "admin"
MAX_ATTEMPTS = 3
BAN_TIME = 300  # seconds

# ---------------- Persistent Folder ----------------
BASE_DIR = Path(os.environ["USERPROFILE"]) / "BSoDs-HTTPS-FS"
BASE_DIR.mkdir(parents=True, exist_ok=True)

CERT_FILE = BASE_DIR / "cert.pem"
KEY_FILE = BASE_DIR / "key.pem"
HASH_FILE = BASE_DIR / ".password_hash"

# ---------------- Argon2 + fail2ban ----------------
ph = PasswordHasher()
failed_attempts = {}
banned_ips = {}

# ---------------- Certificate handling ----------------
def cert_expired(cert_path=CERT_FILE):
    if not cert_path.exists():
        return True
    cert_data = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return datetime.now(timezone.utc) > cert_data.not_valid_after_utc

def generate_cert(cert_path=CERT_FILE, key_path=KEY_FILE):
    print("Generating ECC self-signed cert...")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Generated {cert_path} and {key_path}")

def ensure_cert():
    if not CERT_FILE.exists() or not KEY_FILE.exists() or cert_expired(CERT_FILE):
        generate_cert()
    else:
        print("Cert is valid, skipping generation.")

# ---------------- Password handling ----------------
def load_or_create_password():
    if HASH_FILE.exists():
        return HASH_FILE.read_text().strip()
    else:
        print("No password hash found. Please set a password for the server:")
        while True:
            pw = getpass("Enter password: ")
            pw2 = getpass("Confirm password: ")
            if pw != pw2:
                print("Passwords do not match. Try again.")
            elif len(pw) < 6:
                print("Password too short. Minimum 6 characters.")
            else:
                break
        hash_pw = ph.hash(pw)
        HASH_FILE.write_text(hash_pw)
        print("Password saved.")
        return hash_pw

PASSWORD_HASH = load_or_create_password()
ensure_cert()

# ---------------- HTTP handler ----------------
class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        ip = self.client_address[0]
        if self.is_banned(ip):
            self.send_banned()
            return
        if not self.is_authenticated():
            self.register_failure(ip)
            self.send_auth_required()
            return
        self.reset_attempts(ip)
        super().do_GET()

    def is_authenticated(self):
        auth_header = self.headers.get("Authorization")
        if not auth_header:
            return False
        try:
            auth_type, encoded = auth_header.split(" ", 1)
            if auth_type != "Basic":
                return False
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
            if not hmac.compare_digest(username, USERNAME):
                return False
            ph.verify(PASSWORD_HASH, password)
            return True
        except (ValueError, VerifyMismatchError):
            return False

    def is_banned(self, ip):
        if ip in banned_ips and time.time() < banned_ips[ip]:
            return True
        elif ip in banned_ips:
            del banned_ips[ip]
        return False

    def register_failure(self, ip):
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        if failed_attempts[ip] >= MAX_ATTEMPTS:
            banned_ips[ip] = time.time() + BAN_TIME
            print(f"[BAN] {ip} banned for {BAN_TIME} seconds")
            del failed_attempts[ip]

    def reset_attempts(self, ip):
        if ip in failed_attempts:
            del failed_attempts[ip]

    def send_auth_required(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Secure Area"')
        self.end_headers()
        self.wfile.write(b"Authentication required.")

    def send_banned(self):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"You are temporarily banned. Try again later.")

# ---------------- Cloudflare Tunnel ----------------
def start_cloudflared_tunnel():
    try:
        print("Starting Cloudflare Tunnel...")
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"https://localhost:{PORT}", "--no-tls-verify"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        for line in proc.stdout:
            print(line.strip())
            if ".trycloudflare.com" in line:
                print("Tunnel ready!")
                break
        return proc
    except FileNotFoundError:
        print("cloudflared not found. Install it first.")
        return None

# ---------------- Main ----------------
def run_server():
    os.chdir(SERVE_DIR)  # serve files from chosen directory
    handler_class = lambda *args, **kwargs: AuthHandler(*args, directory=str(SERVE_DIR), **kwargs)
    httpd = http.server.HTTPServer(("0.0.0.0", PORT), handler_class)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    tunnel_proc = None
    if ENABLE_CLOUDFLARE:
        tunnel_proc = start_cloudflared_tunnel()

    print(f"Serving on https://0.0.0.0:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        httpd.server_close()
        if tunnel_proc:
            tunnel_proc.terminate()

if __name__ == "__main__":
    run_server()
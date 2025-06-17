from flask import Flask, request, jsonify, g, Response, abort, render_template, redirect, url_for, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from time import time
import os
import csv
import subprocess
import platform
from datetime import datetime
import uuid
import logging
from collections import defaultdict
import threading
from functools import wraps
import io
import requests
import re
import socket
import pickle
import sqlite3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("security.log"), logging.StreamHandler()]
)
logger = logging.getLogger("security")

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Replace with a fixed secret in production
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database setup
def init_db():
    try:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
            )''')
            # Create default admin user if none exists
            c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            if c.fetchone()[0] == 0:
                default_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
                c.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                          ('admin', 'admin@example.com', default_password, 'admin'))
            conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# Initialize database
if not os.path.exists('users.db'):
    init_db()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    try:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            if user:
                return User(user[0], user[1], user[2], user[3])
            return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None

# Load configuration
class Config:
    BLACKLIST_FILE = "blacklist.txt"
    LOG_FILE = "attacker_log.csv"
    TRUSTED_IPS_FILE = "trusted_ips.txt"
    RATE_LIMIT = 50
    WINDOW_SIZE = 60
    ATTACK_LOG_FILE = "attack_log.csv"
    ATTACK_LOG_FIELDS = [
        "timestamp", "event_name", "violation_type", "signature_name", "source_ip",
        "destination_ip", "source_port", "destination_port", "device_action",
        "requested_url", "response_code", "referer", "user_agent"
    ]
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    MAX_REQUEST_HEADERS = 50
    MAX_HEADER_SIZE = 8192
    MAX_TOTAL_HEADER_SIZE = 100 * 1024
    MAX_REQUEST_PROCESSING_TIME = 30
    REQUEST_TIMEOUT = 10
    MAX_CONCURRENT_REQUESTS_PER_IP = 10
    TELEGRAM_BOT_TOKEN = "7767260738:AAE2FYABGh91dRQEAMm9NQBHkr0QSEmQZ-I"  # Telegram Bot Token
    TELEGRAM_CHAT_ID = "1333522923"    # Telegram Chat ID for alerts

config = Config()

# Load ML model
try:
    loaded_model = pickle.load(open('waf_model.sav', 'rb'))
except Exception as e:
    logger.error(f"Error loading ML model: {e}")
    loaded_model = None

# VirusTotal API configuration
VT_API_KEY = "f46e41d8bbafc4d6a16baa759702f3473056ad64fbefdf1534d764b96f8566ca"
VT_CACHE_DURATION = 86400

# Global state
visits = defaultdict(list)
blacklist = set()
trusted_ips = set()
ip_to_mac = {}
last_saved = time()
concurrent_requests = defaultdict(int)
slow_request_counter = defaultdict(int)
vt_cache = {}

# Thread lock
data_lock = threading.RLock()

# Set global request size limit
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# Regex patterns for malicious payload detection (fallback)
MALICIOUS_PATTERNS = [
    re.compile(r"(\bOR\b\s+['\"]\d+['\"]\s*=\s*['\"]\d+['\"])|(\bUNION\s+SELECT\b)", re.IGNORECASE),
    re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE),
    re.compile(r";\s*(cat|rm|ls|whoami|id)\b", re.IGNORECASE),
]

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

def is_ip_malicious(ip_address, api_key=VT_API_KEY):
    now = time()
    with data_lock:
        if ip_address in vt_cache:
            timestamp, is_malicious, details = vt_cache[ip_address]
            if now - timestamp < VT_CACHE_DURATION:
                logger.debug(f"Using cached VirusTotal result for {ip_address}: {details['status']}")
                return is_malicious, details
    
    if not is_valid_ip(ip_address):
        return False, {"status": "ERROR", "reason": "Invalid IP address format"}
    
    vt_base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    try:
        response = requests.get(f"{vt_base_url}{ip_address}", headers=headers)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        logger.warning(f"VirusTotal API error for {ip_address}: {str(e)}")
        return False, {"status": "ERROR", "reason": f"API error: {str(e)}"}
    
    try:
        attributes = data.get("data", {}).get("attributes", {})
        malicious_count = attributes.get("last_analysis_stats", {}).get("malicious", 0)
        suspicious_count = attributes.get("last_analysis_stats", {}).get("suspicious", 0)
        
        details = {
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "country": attributes.get("country", "Unknown"),
        }
        
        if malicious_count >= 2:
            details["status"] = "MALICIOUS"
            details["reason"] = f"Detected as malicious by {malicious_count} security vendors"
            is_malicious = True
        elif malicious_count == 1 or suspicious_count >= 2:
            details["status"] = "SUSPICIOUS"
            details["reason"] = f"Flagged suspicious by {suspicious_count} vendors, malicious by {malicious_count}"
            is_malicious = False
        else:
            details["status"] = "SAFE"
            details["reason"] = "No significant threats detected"
            is_malicious = False
        
        with data_lock:
            vt_cache[ip_address] = (now, is_malicious, details)
        
        return is_malicious, details
    
    except Exception as e:
        logger.error(f"Error processing VirusTotal results for {ip_address}: {e}")
        return False, {"status": "ERROR", "reason": f"Error processing results: {str(e)}"}

def send_telegram_alert(source_ip, source_port, dest_ip, dest_port, attack_type, mac_address):
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        logger.warning("Telegram alert not sent: Bot token or chat ID not configured")
        return False
    
    message = (
        "🚨 WAF Security Alert 🚨\n"
        f"Source IP: {source_ip}\n"
        f"Source Port: {source_port}\n"
        f"Destination IP: {dest_ip}\n"
        f"Destination Port: {dest_port}\n"
        f"Attack Type: {attack_type}\n"
        f"MAC Address: {mac_address}"
    )
    
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        logger.info(f"Telegram alert sent for attack from {source_ip}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")
        return False

def load_trusted_ips():
    if not os.path.exists(config.TRUSTED_IPS_FILE):
        default_trusted = ["127.0.0.1", "::1"]
        try:
            with open(config.TRUSTED_IPS_FILE, "w") as f:
                for ip in default_trusted:
                    f.write(f"{ip}\n")
            logger.info(f"Created default trusted IPs file with {', '.join(default_trusted)}")
            return set(default_trusted)
        except Exception as e:
            logger.error(f"Error creating trusted IPs file: {e}")
            return set(default_trusted)
    
    try:
        with open(config.TRUSTED_IPS_FILE, "r") as f:
            ips = set(line.strip() for line in f if line.strip())
            logger.info(f"Loaded {len(ips)} trusted IPs")
            return ips
    except Exception as e:
        logger.error(f"Error loading trusted IPs: {e}")
        return {"127.0.0.1", "::1"}

def save_trusted_ips():
    try:
        with open(config.TRUSTED_IPS_FILE, "w") as f:
            for ip in sorted(trusted_ips):
                f.write(f"{ip}\n")
        logger.info(f"Saved {len(trusted_ips)} trusted IPs to file")
    except Exception as e:
        logger.error(f"Error saving trusted IPs: {e}")

def require_trusted_ip(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        if ip not in trusted_ips:
            logger.warning(f"Unauthorized access attempt to admin endpoint from {ip}")
            return jsonify({"error": "Access denied - Trusted IP required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            logger.warning(f"Unauthorized access attempt to admin route by {current_user.username if current_user.is_authenticated else 'anonymous'}")
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def load_blacklist():
    if not os.path.exists(config.BLACKLIST_FILE):
        try:
            with open(config.BLACKLIST_FILE, "w") as f:
                f.write("")
            logger.info("Created empty blacklist file")
            return set()
        except Exception as e:
            logger.error(f"Error creating blacklist file: {e}")
            return set()
    try:
        with open(config.BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except Exception as e:
        logger.error(f"Error loading blacklist: {e}")
        return set()

def save_blacklist():
    try:
        with open(config.BLACKLIST_FILE, "w") as f:
            for ip in sorted(blacklist):
                f.write(f"{ip}\n")
    except Exception as e:
        logger.error(f"Error saving blacklist: {e}")

def get_mac_address(ip, user_agent="Unknown"):
    if ip in ip_to_mac:
        return ip_to_mac[ip]
    
    client_info = f"{ip}{user_agent}"
    pseudo_mac = uuid.uuid5(uuid.NAMESPACE_DNS, client_info).hex[:12]
    formatted_mac = ':'.join(pseudo_mac[i:i+2] for i in range(0, 12, 2))
    
    ip_to_mac[ip] = formatted_mac
    return formatted_mac

def block_ip_in_firewall(ip):
    if ip in trusted_ips:
        logger.warning(f"Attempted to block trusted IP {ip} at firewall level - ignoring")
        return False
        
    try:
        system = platform.system().lower()
        
        if system == "linux":
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logger.info(f"Added {ip} to iptables DROP rule")
        elif system == "windows":
            rule_name = f"Block IP {ip}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", 
                f"remoteip={ip}"
            ], check=True)
            logger.info(f"Added {ip} to Windows Firewall block rule")
        elif system == "darwin":
            with open("/etc/pf.conf", "a") as f:
                f.write(f"\nblock in from {ip} to any\n")
            subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)
            logger.info(f"Added {ip} to macOS pf block rule")
        else:
            logger.warning(f"Unsupported OS: {system}, IP {ip} not blocked at firewall level")
            return False
        return True
    except Exception as e:
        logger.error(f"Failed to block IP {ip} at firewall level: {e}")
        return False

def unblock_ip_from_firewall(ip):
    try:
        system = platform.system().lower()
        
        if system == "linux":
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logger.info(f"Removed {ip} from iptables DROP rule")
        elif system == "windows":
            rule_name = f"Block IP {ip}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}", "dir=in", "remoteip={ip}"
            ], check=True)
            logger.info(f"Removed {ip} from Windows Firewall block rule")
        elif system == "darwin":
            with open("/etc/pf.conf", "r") as f:
                lines = f.readlines()
            with open("/etc/pf.conf", "w") as f:
                for line in lines:
                    if f"block in from {ip} to any" not in line:
                        f.write(line)
            subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)
            logger.info(f"Removed {ip} from macOS pf block rule")
        else:
            logger.warning(f"Unsupported OS: {system}, IP {ip} not unblocked at firewall level")
            return False
    except Exception as e:
        logger.error(f"Failed to unblock IP {ip} at firewall level: {e}")
        return False

def block_ip(ip, reason="rate_limit_exceeded"):
    if ip in trusted_ips:
        logger.warning(f"Attempted to block trusted IP {ip} - ignoring")
        return False
        
    with data_lock:
        if ip not in blacklist:
            blacklist.add(ip)
            user_agent = request.user_agent.string if request.user_agent else "Unknown"
            mac_address = get_mac_address(ip, user_agent)
            request_count = len(visits.get(ip, []))
            firewall_blocked = block_ip_in_firewall(ip)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = [ip, mac_address, request_count, timestamp, reason]
            
            # Send Telegram alert for block action
            source_ip = ip
            source_port = request.environ.get('REMOTE_PORT', 'Unknown')
            dest_ip = request.host if request.host else "Unknown"
            dest_port = request.environ.get('SERVER_PORT', 'Unknown')
            attack_type = reason
            send_telegram_alert(source_ip, source_port, dest_ip, dest_port, attack_type, mac_address)
            
            file_exists = os.path.exists(config.LOG_FILE)
            try:
                with open(config.LOG_FILE, 'a', newline='') as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(['IP Address', 'MAC Address', 'Request Count', 'Timestamp', 'Reason'])
                    writer.writerow(log_entry)
            except Exception as e:
                logger.error(f"Error writing to log file: {e}")
            
            firewall_status = "with firewall block" if firewall_blocked else "application-level only"
            logger.warning(f"BLOCKED: IP={ip}, MAC={mac_address}, Count={request_count}, Reason={reason} ({firewall_status})")
            save_blacklist()
            if ip in visits:
                del visits[ip]
            return True
        return False

def unblock_ip(ip):
    with data_lock:
        if ip in blacklist:
            blacklist.remove(ip)
            firewall_unblocked = unblock_ip_from_firewall(ip)
            logger.info(f"UNBLOCKED: IP={ip} (firewall unblock: {'success' if firewall_unblocked else 'failed'})")
            save_blacklist()
            return True
        return False

def log_attack(request, violation_type, signature_name):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    event_name = "Security Violation"
    source_ip = request.remote_addr
    destination_ip = request.host if request.host else "Unknown"
    source_port = request.environ.get('REMOTE_PORT', 'Unknown')
    destination_port = request.environ.get('SERVER_PORT', 'Unknown')
    device_action = "Blocked"
    requested_url = request.url
    response_code = 403
    referer = request.headers.get('Referer', 'Unknown')
    user_agent = request.user_agent.string if request.user_agent else "Unknown"
    
    log_entry = [
        timestamp, event_name, violation_type, signature_name, source_ip,
        destination_ip, source_port, destination_port, device_action,
        requested_url, response_code, referer, user_agent
    ]
    
    # Send Telegram alert for attack
    mac_address = get_mac_address(source_ip, user_agent)
    send_telegram_alert(source_ip, source_port, destination_ip, destination_port, violation_type, mac_address)
    
    file_exists = os.path.exists(config.ATTACK_LOG_FILE)
    try:
        with open(config.ATTACK_LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(config.ATTACK_LOG_FIELDS)
            writer.writerow(log_entry)
    except Exception as e:
        logger.error(f"Error writing to attack log file: {e}")

class StreamLimiter(io.BufferedReader):
    def __init__(self, ip, raw, *args, **kwargs):
        super().__init__(raw, *args, **kwargs)
        self.ip = ip
        self.start_time = time()
        self.total_read = 0
        self.last_read_time = self.start_time
        self.warning_logged = False
        self.chunk_size = 8192

    def read(self, size=-1):
        current_time = time()
        time_since_last_read = current_time - self.last_read_time
        
        if time_since_last_read > 2.0 and self.total_read > 0 and not self.warning_logged:
            logger.warning(f"Slow request detected from IP {self.ip}: {time_since_last_read:.2f}s since last read")
            self.warning_logged = True
            slow_request_counter[self.ip] += 1
            if slow_request_counter[self.ip] >= 3 and self.ip not in trusted_ips:
                logger.warning(f"Multiple slow requests from IP {self.ip}, blocking")
                block_ip(self.ip, reason="slow_requests")
                raise Exception("Too many slow requests")
        
        if current_time - self.start_time > config.REQUEST_TIMEOUT:
            logger.warning(f"Request timed out from IP {self.ip} after {config.REQUEST_TIMEOUT}s")
            block_ip(self.ip, reason="request_timeout")
            raise Exception("Request timed out")
        
        if size == -1:
            size = self.chunk_size
        data = super().read(min(size, self.chunk_size))
        self.total_read += len(data) if data else 0
        self.last_read_time = current_time
        return data

# Load trusted IPs and blacklist
trusted_ips = load_trusted_ips()
blacklist = load_blacklist()

for ip in blacklist:
    if ip not in trusted_ips:
        block_ip_in_firewall(ip)
logger.info(f"Loaded and blocked {len(blacklist)} blacklisted IPs at firewall level")

@app.before_request
def check_security():
    ip = request.remote_addr
    g.client_ip = ip
    g.start_time = time()
    
    with data_lock:
        concurrent_requests[ip] += 1
    
    if ip in trusted_ips:
        logger.debug(f"Trusted IP {ip} bypassing security checks")
        return None
    
    if ip in blacklist:
        return jsonify({"error": "Access denied"}), 403
    
    is_malicious, details = is_ip_malicious(ip)
    if is_malicious:
        logger.warning(f"Malicious IP detected: {ip}, Status: {details['status']}, Reason: {details['reason']}")
        block_ip(ip, reason=f"malicious_ip:{details['status']}")
        return jsonify({"error": "Access denied - Malicious IP detected"}), 403
    elif details.get('status') == "SUSPICIOUS":
        logger.info(f"Suspicious IP detected: {ip}, Reason: {details['reason']}")
    
    content_length = request.headers.get('Content-Length', type=int)
    if content_length and content_length > config.MAX_CONTENT_LENGTH:
        logger.warning(f"Oversized payload ({content_length} bytes) from IP {ip}")
        block_ip(ip, reason="oversized_payload")
        return jsonify({"error": "Payload too large"}), 413
    
    total_header_size = sum(len(name) + len(value) for name, value in request.headers)
    if total_header_size > config.MAX_TOTAL_HEADER_SIZE:
        logger.warning(f"Excessive total header size ({total_header_size} bytes) from IP {ip}")
        block_ip(ip, reason="excessive_total_header_size")
        return jsonify({"error": "Total header size too large"}), 400
    
    if len(request.headers) > config.MAX_REQUEST_HEADERS:
        logger.warning(f"Excessive headers ({len(request.headers)}) in request from {ip}")
        block_ip(ip, reason="excessive_headers")
        return jsonify({"error": "Too many headers"}), 400
    
    for header_name, header_value in request.headers:
        if len(header_value) > config.MAX_HEADER_SIZE:
            logger.warning(f"Oversized header ({header_name}:{len(header_value)} bytes) in request from {ip}")
            block_ip(ip, reason="oversized_header")
            return jsonify({"error": "Header too large"}), 400
    
    if concurrent_requests[ip] > config.MAX_CONCURRENT_REQUESTS_PER_IP and ip not in trusted_ips:
        logger.warning(f"Too many concurrent requests ({concurrent_requests[ip]}) from IP {ip}")
        block_ip(ip, reason="concurrent_request_limit")
        return jsonify({"error": "Too many concurrent requests"}), 429
    
    with data_lock:
        now = time()
        visits[ip] = [t for t in visits[ip] if t > (now - config.WINDOW_SIZE)]
        visits[ip].append(now)
        if len(visits[ip]) > config.RATE_LIMIT:
            block_ip(ip, reason="rate_limit_exceeded")
            return jsonify({"error": "Too many requests"}), 429
    
    parts_to_check = []
    for key, values in request.args.lists():
        parts_to_check.extend(values)
    for key, values in request.form.lists():
        parts_to_check.extend(values)
    if request.data:
        parts_to_check.append(request.data.decode('utf-8', errors='ignore'))
    
    for part in parts_to_check:
        if loaded_model:
            try:
                prediction = loaded_model.predict([part])[0]
                if prediction != "valid":
                    violation_type = prediction
                    signature_name = part
                    log_attack(request, violation_type, signature_name)
                    block_ip(ip, reason=f"malicious_payload:{violation_type}")
                    return jsonify({"error": "Attack detected"}), 403
            except Exception as e:
                logger.error(f"Error in ML prediction for IP {ip}: {e}")
        
        for pattern, violation_type in [
            (MALICIOUS_PATTERNS[0], "sql_injection"),
            (MALICIOUS_PATTERNS[1], "xss"),
            (MALICIOUS_PATTERNS[2], "command_injection")
        ]:
            if pattern.search(part):
                log_attack(request, violation_type, part)
                block_ip(ip, reason=f"malicious_payload:{violation_type}")
                return jsonify({"error": "Attack detected"}), 403
    
    if request.method == "POST" and request.headers.get('Content-Length'):
        try:
            stream = StreamLimiter(ip, request.environ['wsgi.input'])
            request.stream = stream
        except Exception as e:
            logger.error(f"Error handling request stream: {e}")
            block_ip(ip, reason="stream_error")
            return jsonify({"error": "Invalid request stream"}), 400
    
    return None

@app.after_request
def log_request(response):
    if hasattr(g, 'start_time') and hasattr(g, 'client_ip'):
        ip = g.client_ip
        duration = time() - g.start_time
        status = response.status_code
        
        with data_lock:
            if concurrent_requests[ip] > 0:
                concurrent_requests[ip] -= 1
        
        if duration > config.MAX_REQUEST_PROCESSING_TIME and ip not in trusted_ips:
            logger.warning(f"Request from {ip} took too long: {duration:.2f}s")
            slow_request_counter[ip] += 1
            if slow_request_counter[ip] >= 3:
                block_ip(ip, reason="slow_requests")
                return jsonify({"error": "Too many slow requests"}), 429
        
        if status >= 400 or duration > 1.0:
            logger.info(f"Request from {ip}: status={status}, time={duration:.2f}s, " +
                        f"size={request.headers.get('Content-Length', '0')} bytes")
    
    return response

@app.teardown_request
def cleanup_request(exception=None):
    if hasattr(g, 'client_ip'):
        ip = g.client_ip
        with data_lock:
            if concurrent_requests[ip] > 0:
                concurrent_requests[ip] -= 1
    
    if exception:
        logger.warning(f"Request terminated with exception: {exception}")

class TimeoutMiddleware:
    def __init__(self, app, timeout=config.REQUEST_TIMEOUT):
        self.app = app
        self.timeout = timeout

    def __call__(self, environ, start_response):
        start_time = time()
        
        def timeout_start_response(status, headers, exc_info=None):
            if time() - start_time > self.timeout:
                return start_response('503 Service Unavailable', [('Content-Type', 'application/json')], exc_info)
            return start_response(status, headers, exc_info)
        
        return self.app(environ, timeout_start_response)

app.wsgi_app = TimeoutMiddleware(app.wsgi_app)

# Frontend Routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute("SELECT id, username, password_hash, email, role FROM users WHERE username = ?", (username,))
                user = c.fetchone()
        
            if user and bcrypt.check_password_hash(user[2], password):
                user_obj = User(user[0], user[1], user[3], user[4])
                login_user(user_obj)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
        except Exception as e:
            logger.error(f"Error during login for {username}: {e}")
            flash('An error occurred. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route("/")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.remote_addr not in trusted_ips:
        return jsonify({"error": "Access denied - Trusted IP required"}), 403
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
@login_required
@require_trusted_ip
def dashboard():
    for file in [config.ATTACK_LOG_FILE, config.LOG_FILE]:
        if not os.path.exists(file):
            try:
                with open(file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    if file == config.ATTACK_LOG_FILE:
                        writer.writerow(config.ATTACK_LOG_FIELDS)
                    elif file == config.LOG_FILE:
                        writer.writerow(['IP Address', 'MAC Address', 'Request Count', 'Timestamp', 'Reason'])
                logger.info(f"Created empty {file}")
            except Exception as e:
                logger.error(f"Error creating {file}: {e}")
    return render_template('dashboard.html')

@app.route("/blacklist-page")
@login_required
@require_trusted_ip
def blacklist_page():
    return render_template('blacklist.html')

@app.route("/trusted-page")
@login_required
@require_trusted_ip
def trusted_page():
    return render_template('trusted.html')

@app.route("/check-ip-page")
@login_required
@require_trusted_ip
def check_ip_page():
    return render_template('check_ip.html')

@app.route("/settings")
@login_required
@require_trusted_ip
def settings():
    return render_template('settings.html', config=config.__dict__)

@app.route("/manage-users", methods=["GET", "POST"])
@login_required
@require_trusted_ip
@require_admin
def manage_users():
    if request.method == "POST":
        action = request.form.get('action')
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                if action == "add":
                    username = request.form.get('username')
                    email = request.form.get('email')
                    password = request.form.get('password')
                    role = request.form.get('role')
                    c.execute("SELECT username FROM users WHERE username = ?", (username,))
                    if c.fetchone():
                        flash('Username already exists.', 'danger')
                    else:
                        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
                        c.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                                  (username, email, password_hash, role))
                        conn.commit()
                        flash('User added successfully.', 'success')
                elif action == "edit":
                    user_id = request.form.get('user_id')
                    username = request.form.get('username')
                    email = request.form.get('email')
                    role = request.form.get('role')
                    c.execute("SELECT username FROM users WHERE username = ? AND id != ?", (username, user_id))
                    if c.fetchone():
                        flash('Username already exists.', 'danger')
                    else:
                        c.execute("UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
                                  (username, email, role, user_id))
                        conn.commit()
                        flash('User updated successfully.', 'success')
                elif action == "delete":
                    user_id = request.form.get('user_id')
                    if str(user_id) == str(current_user.id):
                        flash('Cannot delete your own account.', 'danger')
                    else:
                        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
                        conn.commit()
                        flash('User deleted successfully.', 'success')
        except Exception as e:
            logger.error(f"Error in manage_users: {e}")
            flash('An error occurred. Please try again.', 'danger')
    
    try:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, email, role FROM users")
            users = c.fetchall()
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        users = []
    
    return render_template('manage_users.html', users=users)

# Backend API Routes
@app.route("/block/<ip_address>", methods=["POST"])
@login_required
@require_trusted_ip
def manual_block(ip_address):
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    if ip_address in trusted_ips:
        return jsonify({"status": "error", "message": "Cannot block a trusted IP"}), 400
        
    success = block_ip(ip_address, "manual_block")
    if success:
        return jsonify({"status": "success", "message": f"IP {ip_address} blocked"})
    else:
        return jsonify({"status": "info", "message": f"IP {ip_address} was already blocked"}), 200

@app.route("/unblock/<ip_address>", methods=["POST"])
@login_required
@require_trusted_ip
def manual_unblock(ip_address):
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    success = unblock_ip(ip_address)
    if success:
        return jsonify({"status": "success", "message": f"IP {ip_address} unblocked"})
    else:
        return jsonify({"status": "info", "message": f"IP {ip_address} was not in the blacklist"}), 200

@app.route("/blacklist", methods=["GET"])
@login_required
@require_trusted_ip
def get_blacklist():
    with data_lock:
        return jsonify({"blacklist": list(blacklist)})

@app.route("/trusted", methods=["GET"])
@login_required
@require_trusted_ip
def get_trusted_ips():
    with data_lock:
        return jsonify({"trusted_ips": list(trusted_ips)})

@app.route("/trusted/add/<ip_address>", methods=["POST"])
@login_required
@require_trusted_ip
def add_trusted_ip(ip_address):
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    with data_lock:
        if ip_address in trusted_ips:
            return jsonify({"status": "info", "message": f"IP {ip_address} is already trusted"}), 200
            
        trusted_ips.add(ip_address)
        save_trusted_ips()
        
        if ip_address in blacklist:
            unblock_ip(ip_address)
            
        logger.info(f"Added {ip_address} to trusted IPs list")
        return jsonify({"status": "success", "message": f"IP {ip_address} added to trusted IPs"})

@app.route("/trusted/remove/<ip_address>", methods=["POST"])
@login_required
@require_trusted_ip
def remove_trusted_ip(ip_address):
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    current_ip = request.remote_addr
    if ip_address == current_ip:
        logger.warning(f"Attempt to remove own IP ({current_ip}) from trusted list - denied")
        return jsonify({"status": "error", "message": "Cannot remove your own IP from trusted list"}), 400
    
    with data_lock:
        if ip_address not in trusted_ips:
            return jsonify({"status": "info", "message": f"IP {ip_address} is not in trusted list"}), 200
            
        trusted_ips.remove(ip_address)
        save_trusted_ips()
        
        logger.info(f"Removed {ip_address} from trusted IPs list")
        return jsonify({"status": "success", "message": f"IP {ip_address} removed from trusted IPs"})

@app.route("/stats", methods=["GET"])
@login_required
@require_trusted_ip
def get_stats():
    with data_lock:
        now = time()
        active_ips = {ip: len(timestamps) for ip, timestamps in visits.items() 
                     if timestamps and timestamps[-1] > (now - 300)}
        
        return jsonify({
            "blacklist_size": len(blacklist),
            "trusted_ips_count": len(trusted_ips),
            "active_ips": len(active_ips),
            "high_rate_ips": {ip: count for ip, count in active_ips.items() if count > (config.RATE_LIMIT // 2)},
            "concurrent_requests": {ip: count for ip, count in concurrent_requests.items() if count > 0},
            "slow_request_offenders": {ip: count for ip, count in slow_request_counter.items() if count > 0}
        })

@app.route("/reset-slow-counter/<ip_address>", methods=["POST"])
@login_required
@require_trusted_ip
def reset_slow_counter(ip_address):
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    with data_lock:
        if ip_address in slow_request_counter:
            count = slow_request_counter[ip_address]
            slow_request_counter[ip_address] = 0
            return jsonify({"status": "success", "message": f"Reset slow counter for {ip_address} (was {count})"})
        return jsonify({"status": "info", "message": f"IP {ip_address} has no slow request count"}), 200

@app.route("/check-ip/<ip_address>", methods=["GET"])
@login_required
@require_trusted_ip
def check_ip(ip_address):
    is_malicious, details = is_ip_malicious(ip_address)
    result = {
        "ip": ip_address,
        "is_malicious": is_malicious,
        "status": details.get("status", "UNKNOWN"),
        "details": details
    }
    return jsonify(result)

@app.route("/clear-vt-cache", methods=["POST"])
@login_required
@require_trusted_ip
def clear_vt_cache():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    with data_lock:
        cache_size = len(vt_cache)
        vt_cache.clear()
        return jsonify({"status": "success", "message": f"Cleared VirusTotal cache ({cache_size} entries)"})

@app.route("/attack-log", methods=["GET"])
@login_required
@require_trusted_ip
def get_attack_log():
    logs = []
    try:
        if os.path.exists(config.ATTACK_LOG_FILE) and os.access(config.ATTACK_LOG_FILE, os.R_OK):
            with open(config.ATTACK_LOG_FILE, 'r', newline='') as f:
                reader = csv.DictReader(f)
                if reader.fieldnames:
                    logs = list(reader)
                else:
                    logger.warning(f"Empty or invalid {config.ATTACK_LOG_FILE}")
        else:
            logger.info(f"{config.ATTACK_LOG_FILE} does not exist or is not readable")
    except Exception as e:
        logger.error(f"Error reading {config.ATTACK_LOG_FILE}: {e}")
    return jsonify({"logs": logs})

@app.route("/attacker-log", methods=["GET"])
@login_required
@require_trusted_ip
def get_attacker_log():
    logs = []
    try:
        if os.path.exists(config.LOG_FILE) and os.access(config.LOG_FILE, os.R_OK):
            with open(config.LOG_FILE, 'r', newline='') as f:
                reader = csv.DictReader(f)
                if reader.fieldnames:
                    logs = list(reader)
                else:
                    logger.warning(f"Empty or invalid {config.LOG_FILE}")
        else:
            logger.info(f"{config.LOG_FILE} does not exist or is not readable")
    except Exception as e:
        logger.error(f"Error reading {config.LOG_FILE}: {e}")
    return jsonify({"logs": logs})

@app.route("/security-log", methods=["GET"])
@login_required
@require_trusted_ip
def get_security_log():
    logs = []
    try:
        if os.path.exists("security.log") and os.access("security.log", os.R_OK):
            with open("security.log", 'r') as f:
                logs = f.readlines()[-100:]
        else:
            logger.info("security.log does not exist or is not readable")
    except Exception as e:
        logger.error(f"Error reading security.log: {e}")
    return jsonify({"logs": logs})

@app.route("/export-attack-log", methods=["GET"])
@login_required
@require_trusted_ip
def export_attack_log():
    try:
        if os.path.exists(config.ATTACK_LOG_FILE):
            return send_file(config.ATTACK_LOG_FILE, as_attachment=True, download_name="attack_log.csv")
        else:
            return jsonify({"error": "Attack log file not found"}), 404
    except Exception as e:
        logger.error(f"Error exporting attack log: {e}")
        return jsonify({"error": "Unable to export attack log"}), 500

@app.route("/export-attacker-log", methods=["GET"])
@login_required
@require_trusted_ip
def export_attacker_log():
    try:
        if os.path.exists(config.LOG_FILE):
            return send_file(config.LOG_FILE, as_attachment=True, download_name="attacker_log.csv")
        else:
            return jsonify({"error": "Attacker log file not found"}), 404
    except Exception as e:
        logger.error(f"Error exporting attacker log: {e}")
        return jsonify({"error": "Unable to export attacker log"}), 500

@app.route("/delete-log/<log_type>", methods=["POST"])
@login_required
@require_trusted_ip
def delete_log(log_type):
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    file_map = {
        "attack": config.ATTACK_LOG_FILE,
        "attacker": config.LOG_FILE,
        "security": "security.log"
    }
    file_path = file_map.get(log_type)
    if not file_path:
        return jsonify({"status": "error", "message": "Invalid log type"}), 400
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Deleted {file_path}")
            if log_type in ["attack", "attacker"]:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    if log_type == "attack":
                        writer.writerow(config.ATTACK_LOG_FIELDS)
                    elif log_type == "attacker":
                        writer.writerow(['IP Address', 'MAC Address', 'Request Count', 'Timestamp', 'Reason'])
            return jsonify({"status": "success", "message": f"Deleted {log_type} log"})
        else:
            return jsonify({"status": "info", "message": f"{log_type} log not found"}), 200
    except Exception as e:
        logger.error(f"Error deleting {file_path}: {e}")
        return jsonify({"status": "error", "message": f"Failed to delete {log_type} log"}), 500

@app.route("/update-settings", methods=["POST"])
@login_required
@require_trusted_ip
def update_settings():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin privileges required"}), 403
    try:
        data = request.json
        for key, value in data.items():
            if hasattr(config, key):
                if key in ["RATE_LIMIT", "WINDOW_SIZE", "MAX_CONTENT_LENGTH", "MAX_REQUEST_HEADERS", 
                          "MAX_HEADER_SIZE", "MAX_REQUEST_PROCESSING_TIME", "REQUEST_TIMEOUT", 
                          "MAX_CONCURRENT_REQUESTS_PER_IP"]:
                    setattr(config, key, int(value))
                elif key in ["BLACKLIST_FILE", "LOG_FILE", "TRUSTED_IPS_FILE", "ATTACK_LOG_FILE",
                            "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"]:
                    setattr(config, key, str(value))
        if data.get("TRUSTED_IPS_FILE") or data.get("BLACKLIST_FILE"):
            trusted_ips.clear()
            blacklist.clear()
            trusted_ips.update(load_trusted_ips())
            blacklist.update(load_blacklist())
            for ip in blacklist:
                if ip not in trusted_ips:
                    block_ip_in_firewall(ip)
        return jsonify({"status": "success", "message": "Settings updated"})
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        return jsonify({"status": "error", "message": "Failed to update settings"}), 500

if __name__ == "__main__":
    logger.info("Starting security server with WAF capabilities...")
    app.run(host="0.0.0.0", port=80)
from flask import Flask, request, jsonify, g, Response, abort
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
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("security.log"), logging.StreamHandler()]
)
logger = logging.getLogger("security")

app = Flask(__name__)

# Configuration
BLACKLIST_FILE = "blacklist.txt"
LOG_FILE = "attacker_log.csv"
TRUSTED_IPS_FILE = "trusted_ips.txt"
RATE_LIMIT = 50  # max requests per minute
WINDOW_SIZE = 60  # in seconds

# Heavy request mitigation configuration
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB max request size
MAX_REQUEST_HEADERS = 50  # Maximum number of headers allowed
MAX_HEADER_SIZE = 8192  # Maximum size of any single header (8KB)
MAX_REQUEST_PROCESSING_TIME = 30  # Maximum time to process a request (seconds)
REQUEST_TIMEOUT = 45  # Timeout for slow requests (seconds)
MAX_CONCURRENT_REQUESTS_PER_IP = 10  # Maximum concurrent requests per IP

# VirusTotal API configuration
VT_API_KEY = "f46e41d8bbafc4d6a16baa759702f3473056ad64fbefdf1534d764b96f8566ca"  # Replace with your actual API key
VT_CACHE_DURATION = 86400  # Cache IP check results for 24 hours (in seconds)

# Global state
visits = defaultdict(list)  # IP -> list of timestamps
blacklist = set()           # Blocked IPs
trusted_ips = set()         # Trusted IPs for administration
ip_to_mac = {}              # Maps IPs to MAC addresses
last_saved = time()         # Last time data was saved
concurrent_requests = defaultdict(int)  # Track concurrent requests by IP
slow_request_counter = defaultdict(int)  # Track slow requests by IP
vt_cache = {}               # Cache for VirusTotal results {ip: (timestamp, is_malicious, details)}

# Thread lock
data_lock = threading.RLock()

# Set global request size limit
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def is_valid_ip(ip):
    """Validate IPv4 address format"""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

def is_ip_malicious(ip_address, api_key=VT_API_KEY):
    """
    Check if an IP address is malicious using VirusTotal API.
    
    Args:
        ip_address (str): The IP address to check
        api_key (str): VirusTotal API key (using the one from original code by default)
        
    Returns:
        tuple: (is_malicious, details)
            - is_malicious (bool): True if IP is malicious, False otherwise
            - details (dict): Contains information about the scan including:
                - status: "MALICIOUS", "SUSPICIOUS", "SAFE", or "ERROR"
                - reason: Explanation of the result
                - malicious_count: Number of engines detecting as malicious
    """
    # Check cache first
    now = time()
    with data_lock:
        if ip_address in vt_cache:
            timestamp, is_malicious, details = vt_cache[ip_address]
            # If cache is not expired
            if now - timestamp < VT_CACHE_DURATION:
                logger.debug(f"Using cached VirusTotal result for {ip_address}: {details['status']}")
                return is_malicious, details
    
    # Validate IP address format
    if not is_valid_ip(ip_address):
        return False, {"status": "ERROR", "reason": "Invalid IP address format"}
    
    # API setup
    vt_base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    # Try to get data from VirusTotal
    try:
        response = requests.get(f"{vt_base_url}{ip_address}", headers=headers)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        logger.warning(f"VirusTotal API error for {ip_address}: {str(e)}")
        return False, {"status": "ERROR", "reason": f"API error: {str(e)}"}
    
    # Extract relevant data
    try:
        attributes = data.get("data", {}).get("attributes", {})
        malicious_count = attributes.get("last_analysis_stats", {}).get("malicious", 0)
        suspicious_count = attributes.get("last_analysis_stats", {}).get("suspicious", 0)
        
        # Create result details
        details = {
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "country": attributes.get("country", "Unknown"),
        }
        
        # Determine status based on detection counts
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
            
        # Cache the result
        with data_lock:
            vt_cache[ip_address] = (now, is_malicious, details)
            
        return is_malicious, details
            
    except Exception as e:
        logger.error(f"Error processing VirusTotal results for {ip_address}: {str(e)}")
        return False, {"status": "ERROR", "reason": f"Error processing results: {str(e)}"}



def load_trusted_ips():
    """Load trusted IPs from file"""
    if not os.path.exists(TRUSTED_IPS_FILE):
        # Create default trusted IPs file with localhost
        default_trusted = ["127.0.0.1", "::1"]
        try:
            with open(TRUSTED_IPS_FILE, "w") as f:
                for ip in default_trusted:
                    f.write(f"{ip}\n")
            logger.info(f"Created default trusted IPs file with {', '.join(default_trusted)}")
            return set(default_trusted)
        except Exception as e:
            logger.error(f"Error creating trusted IPs file: {e}")
            return set(default_trusted)
    
    try:
        with open(TRUSTED_IPS_FILE, "r") as f:
            ips = set(line.strip() for line in f if line.strip())
            logger.info(f"Loaded {len(ips)} trusted IPs")
            return ips
    except Exception as e:
        logger.error(f"Error loading trusted IPs: {e}")
        return {"127.0.0.1", "::1"}  # Default to localhost

def save_trusted_ips():
    """Save trusted IPs to file"""
    try:
        with open(TRUSTED_IPS_FILE, "w") as f:
            for ip in sorted(trusted_ips):
                f.write(f"{ip}\n")
        logger.info(f"Saved {len(trusted_ips)} trusted IPs to file")
    except Exception as e:
        logger.error(f"Error saving trusted IPs: {e}")

def require_trusted_ip(f):
    """Decorator to require a trusted IP for access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        if ip not in trusted_ips:
            logger.warning(f"Unauthorized access attempt to admin endpoint from {ip}")
            return jsonify({"error": "Access denied"}), 403
        return f(*args, **kwargs)
    return decorated_function

def load_blacklist():
    """Load blacklisted IPs from file"""
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except Exception as e:
        logger.error(f"Error loading blacklist: {e}")
        return set()

def save_blacklist():
    """Save blacklisted IPs to file"""
    try:
        with open(BLACKLIST_FILE, "w") as f:
            for ip in sorted(blacklist):
                f.write(f"{ip}\n")
    except Exception as e:
        logger.error(f"Error saving blacklist: {e}")

def get_mac_address(ip, user_agent="Unknown"):
    """Generate a consistent MAC address for this IP"""
    if ip in ip_to_mac:
        return ip_to_mac[ip]
    
    # Create a pseudo-MAC based on IP and user agent
    client_info = f"{ip}{user_agent}"
    pseudo_mac = uuid.uuid5(uuid.NAMESPACE_DNS, client_info).hex[:12]
    formatted_mac = ':'.join(pseudo_mac[i:i+2] for i in range(0, 12, 2))
    
    # Store the mapping
    ip_to_mac[ip] = formatted_mac
    return formatted_mac

def block_ip_in_firewall(ip):
    """Block IP at the firewall/system level"""
    # Don't block trusted IPs at the firewall level
    if ip in trusted_ips:
        logger.warning(f"Attempted to block trusted IP {ip} at firewall level - ignoring")
        return False
        
    try:
        system = platform.system().lower()
        
        if system == "linux":
            # Use iptables on Linux
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logger.info(f"Added {ip} to iptables DROP rule")
            
        elif system == "windows":
            # Use Windows Firewall
            rule_name = f"Block IP {ip}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", 
                f"remoteip={ip}"
            ], check=True)
            logger.info(f"Added {ip} to Windows Firewall block rule")
            
        elif system == "darwin":  # macOS
            # Use pf on macOS
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
    """Unblock IP at the firewall/system level"""
    try:
        system = platform.system().lower()
        
        if system == "linux":
            # Use iptables on Linux
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logger.info(f"Removed {ip} from iptables DROP rule")
            
        elif system == "windows":
            # Use Windows Firewall
            rule_name = f"Block IP {ip}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}", "dir=in", "remoteip={ip}"
            ], check=True)
            logger.info(f"Removed {ip} from Windows Firewall block rule")
            
        elif system == "darwin":  # macOS
            # Read current pf.conf
            with open("/etc/pf.conf", "r") as f:
                lines = f.readlines()
            
            # Remove the block rule for this IP
            with open("/etc/pf.conf", "w") as f:
                for line in lines:
                    if f"block in from {ip} to any" not in line:
                        f.write(line)
            
            # Reload pf
            subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)
            logger.info(f"Removed {ip} from macOS pf block rule")
            
        else:
            logger.warning(f"Unsupported OS: {system}, IP {ip} not unblocked at firewall level")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Failed to unblock IP {ip} at firewall level: {e}")
        return False

def block_ip(ip, reason="rate_limit_exceeded"):
    """Block an IP and log it"""
    # Don't block trusted IPs
    if ip in trusted_ips:
        logger.warning(f"Attempted to block trusted IP {ip} - ignoring")
        return False
        
    with data_lock:
        if ip not in blacklist:
            blacklist.add(ip)
            
            # Get MAC address
            user_agent = request.user_agent.string if request.user_agent else "Unknown"
            mac_address = get_mac_address(ip, user_agent)
            
            # Get request count
            request_count = len(visits.get(ip, []))
            
            # Block at firewall level
            firewall_blocked = block_ip_in_firewall(ip)
            
            # Add to log file
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = [ip, mac_address, request_count, timestamp, reason]
            
            # Log to CSV
            file_exists = os.path.exists(LOG_FILE)
            try:
                with open(LOG_FILE, 'a', newline='') as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(['IP Address', 'MAC Address', 'Request Count', 'Timestamp', 'Reason'])
                    writer.writerow(log_entry)
            except Exception as e:
                logger.error(f"Error writing to log file: {e}")
            
            # Log to console/file
            firewall_status = "with firewall block" if firewall_blocked else "application-level only"
            logger.warning(f"BLOCKED: IP={ip}, MAC={mac_address}, Count={request_count}, Reason={reason} ({firewall_status})")
            
            # Save blacklist to file
            save_blacklist()
            
            # Clean up
            if ip in visits:
                del visits[ip]
            
            return True
        return False

def unblock_ip(ip):
    """Unblock an IP address"""
    with data_lock:
        if ip in blacklist:
            # Remove from blacklist
            blacklist.remove(ip)
            
            # Unblock at firewall level
            firewall_unblocked = unblock_ip_from_firewall(ip)
            
            # Log the unblock
            logger.info(f"UNBLOCKED: IP={ip} (firewall unblock: {'success' if firewall_unblocked else 'failed'})")
            
            # Save updated blacklist to file
            save_blacklist()
            
            return True
        return False

class StreamLimiter(io.BytesIO):
    """Stream limiter to prevent slow request attacks"""
    def __init__(self, ip, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip = ip
        self.start_time = time()
        self.total_read = 0
        self.last_read_time = self.start_time
        self.warning_logged = False

    def read(self, size=-1):
        current_time = time()
        time_since_last_read = current_time - self.last_read_time
        
        # If we haven't read anything in a while, detect slow request
        if time_since_last_read > 2.0 and self.total_read > 0 and not self.warning_logged:
            logger.warning(f"Slow request detected from IP {self.ip}: {time_since_last_read:.2f}s since last read")
            self.warning_logged = True
            slow_request_counter[self.ip] += 1
            
            # If this IP has multiple slow requests, consider blocking
            if slow_request_counter[self.ip] >= 3 and self.ip not in trusted_ips:
                logger.warning(f"Multiple slow requests from IP {self.ip}, considering blocking")
                
        # Enforce timeout
        if current_time - self.start_time > REQUEST_TIMEOUT:
            logger.warning(f"Request timed out from IP {self.ip} after {REQUEST_TIMEOUT}s")
            raise Exception("Request timed out")
        
        # Read the data
        data = super().read(size)
        self.total_read += len(data) if data else 0
        self.last_read_time = current_time
        return data

# Load trusted IPs and blacklist
trusted_ips = load_trusted_ips()
blacklist = load_blacklist()

# Apply firewall rules for blacklisted IPs
for ip in blacklist:
    if ip not in trusted_ips:  # Extra safety check
        block_ip_in_firewall(ip)
logger.info(f"Loaded and blocked {len(blacklist)} blacklisted IPs at firewall level")

@app.before_request
def check_security():
    """Check each request for security issues"""
    ip = request.remote_addr
    
    # Store client info
    g.client_ip = ip
    g.start_time = time()
    
    # Increment concurrent request counter
    with data_lock:
        concurrent_requests[ip] += 1
    
    # Trusted IPs bypass blacklist and rate limiting
    if ip in trusted_ips:
        logger.debug(f"Trusted IP {ip} bypassing security checks")
        return None
    
    # Block if IP is blacklisted (backup in case firewall fails)
    if ip in blacklist:
        return jsonify({"error": "Access denied"}), 403
    
    # ** NEW: Check if IP is malicious via VirusTotal **
    is_malicious, details = is_ip_malicious(ip)
    if is_malicious:
        logger.warning(f"Malicious IP detected: {ip}, Status: {details['status']}, Reason: {details['reason']}")
        block_ip(ip, reason=f"malicious_ip:{details['status']}")
        return jsonify({"error": "Access denied - Malicious IP detected"}), 403
    elif details.get('status') == "SUSPICIOUS":
        logger.info(f"Suspicious IP detected: {ip}, Reason: {details['reason']}")
    
    # Check for excessive headers
    if len(request.headers) > MAX_REQUEST_HEADERS:
        logger.warning(f"Excessive headers ({len(request.headers)}) in request from {ip}")
        block_ip(ip, reason="excessive_headers")
        return jsonify({"error": "Too many headers"}), 400
    
    # Check header size
    for header_name, header_value in request.headers:
        if len(header_value) > MAX_HEADER_SIZE:
            logger.warning(f"Oversized header ({header_name}:{len(header_value)} bytes) in request from {ip}")
            block_ip(ip, reason="oversized_header")
            return jsonify({"error": "Header too large"}), 400
    
    # Check for too many concurrent requests from same IP
    if concurrent_requests[ip] > MAX_CONCURRENT_REQUESTS_PER_IP and ip not in trusted_ips:
        logger.warning(f"Too many concurrent requests ({concurrent_requests[ip]}) from IP {ip}")
        block_ip(ip, reason="concurrent_request_limit")
        return jsonify({"error": "Too many concurrent requests"}), 429
    
    # Apply rate limiting
    with data_lock:
        now = time()
        # Remove old timestamps
        visits[ip] = [t for t in visits[ip] if t > (now - WINDOW_SIZE)]
        visits[ip].append(now)
        
        # Block if too many requests
        if len(visits[ip]) > RATE_LIMIT:
            block_ip(ip, reason="rate_limit_exceeded")
            return jsonify({"error": "Too many requests"}), 429
    
    # Create streaming limiter for request body
    if request.headers.get('Content-Length'):
        try:
            stream = StreamLimiter(ip, request.get_data())
            request.stream = stream
        except Exception as e:
            logger.error(f"Error handling request stream: {e}")
    
    return None

@app.after_request
def log_request(response):
    """Log request details for monitoring and decrement concurrent request counter"""
    if hasattr(g, 'start_time') and hasattr(g, 'client_ip'):
        ip = g.client_ip
        duration = time() - g.start_time
        status = response.status_code
        
        # Decrement concurrent request counter
        with data_lock:
            if concurrent_requests[ip] > 0:
                concurrent_requests[ip] -= 1
        
        # Block if request took too long and wasn't from trusted IP
        if duration > MAX_REQUEST_PROCESSING_TIME and ip not in trusted_ips:
            logger.warning(f"Request from {ip} took too long: {duration:.2f}s")
            # Consider blocking if this is a frequent offender
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
    """Clean up request resources even if an exception occurred"""
    if hasattr(g, 'client_ip'):
        ip = g.client_ip
        # Ensure we decrement the counter even if an exception occurred
        with data_lock:
            if concurrent_requests[ip] > 0:
                concurrent_requests[ip] -= 1
    
    if exception:
        logger.warning(f"Request terminated with exception: {exception}")

# Add middleware to enforce timeouts on responses
class TimeoutMiddleware:
    def __init__(self, app, timeout=REQUEST_TIMEOUT):
        self.app = app
        self.timeout = timeout

    def __call__(self, environ, start_response):
        start_time = time()
        
        def timeout_start_response(status, headers, exc_info=None):
            if time() - start_time > self.timeout:
                return start_response('503 Service Unavailable', [('Content-Type', 'application/json')], exc_info)
            return start_response(status, headers, exc_info)
        
        return self.app(environ, timeout_start_response)

# Apply middleware
app.wsgi_app = TimeoutMiddleware(app.wsgi_app)

@app.route("/")
def home():
    return "Server is running"

@app.route("/block/<ip_address>", methods=["POST"])
@require_trusted_ip
def manual_block(ip_address):
    """Manually block an IP address"""
    if ip_address in trusted_ips:
        return jsonify({"status": "error", "message": "Cannot block a trusted IP"}), 400
        
    success = block_ip(ip_address, "manual_block")
    if success:
        return jsonify({"status": "success", "message": f"IP {ip_address} blocked"})
    else:
        return jsonify({"status": "info", "message": f"IP {ip_address} was already blocked"}), 200

@app.route("/unblock/<ip_address>", methods=["POST"])
@require_trusted_ip
def manual_unblock(ip_address):
    """Manually unblock an IP address"""
    success = unblock_ip(ip_address)
    if success:
        return jsonify({"status": "success", "message": f"IP {ip_address} unblocked"})
    else:
        return jsonify({"status": "info", "message": f"IP {ip_address} was not in the blacklist"}), 200

@app.route("/blacklist", methods=["GET"])
@require_trusted_ip
def get_blacklist():
    """Return the current blacklist"""
    with data_lock:
        return jsonify({"blacklist": list(blacklist)})

@app.route("/trusted", methods=["GET"])
@require_trusted_ip
def get_trusted_ips():
    """Return the current trusted IPs list"""
    with data_lock:
        return jsonify({"trusted_ips": list(trusted_ips)})

@app.route("/trusted/add/<ip_address>", methods=["POST"])
@require_trusted_ip
def add_trusted_ip(ip_address):
    """Add a new trusted IP"""
    with data_lock:
        if ip_address in trusted_ips:
            return jsonify({"status": "info", "message": f"IP {ip_address} is already trusted"}), 200
            
        # Add to trusted IPs
        trusted_ips.add(ip_address)
        save_trusted_ips()
        
        # If this IP was blocked, unblock it
        if ip_address in blacklist:
            unblock_ip(ip_address)
            
        logger.info(f"Added {ip_address} to trusted IPs list")
        return jsonify({"status": "success", "message": f"IP {ip_address} added to trusted IPs"})

@app.route("/trusted/remove/<ip_address>", methods=["POST"])
@require_trusted_ip
def remove_trusted_ip(ip_address):
    """Remove a trusted IP"""
    current_ip = request.remote_addr
    
    # Prevent removing the IP that's making the request
    if ip_address == current_ip:
        logger.warning(f"Attempt to remove own IP ({current_ip}) from trusted list - denied")
        return jsonify({"status": "error", "message": "Cannot remove your own IP from trusted list"}), 400
    
    with data_lock:
        if ip_address not in trusted_ips:
            return jsonify({"status": "info", "message": f"IP {ip_address} is not in trusted list"}), 200
            
        # Remove from trusted IPs
        trusted_ips.remove(ip_address)
        save_trusted_ips()
        
        logger.info(f"Removed {ip_address} from trusted IPs list")
        return jsonify({"status": "success", "message": f"IP {ip_address} removed from trusted IPs"})

@app.route("/stats", methods=["GET"])
@require_trusted_ip
def get_stats():
    """Return basic stats about current traffic and blacklist"""
    with data_lock:
        now = time()
        active_ips = {ip: len(timestamps) for ip, timestamps in visits.items() 
                     if timestamps and timestamps[-1] > (now - 300)}  # Active in last 5 minutes
        
        return jsonify({
            "blacklist_size": len(blacklist),
            "trusted_ips_count": len(trusted_ips),
            "active_ips": len(active_ips),
            "high_rate_ips": {ip: count for ip, count in active_ips.items() if count > (RATE_LIMIT // 2)},
            "concurrent_requests": {ip: count for ip, count in concurrent_requests.items() if count > 0},
            "slow_request_offenders": {ip: count for ip, count in slow_request_counter.items() if count > 0}
        })

@app.route("/reset-slow-counter/<ip_address>", methods=["POST"])
@require_trusted_ip
def reset_slow_counter(ip_address):
    """Reset slow request counter for an IP"""
    with data_lock:
        if ip_address in slow_request_counter:
            count = slow_request_counter[ip_address]
            slow_request_counter[ip_address] = 0
            return jsonify({"status": "success", "message": f"Reset slow counter for {ip_address} (was {count})"})
        return jsonify({"status": "info", "message": f"IP {ip_address} has no slow request count"}), 200

# NEW: Endpoint to check if an IP is malicious
@app.route("/check-ip/<ip_address>", methods=["GET"])
@require_trusted_ip
def check_ip(ip_address):
    """Check if an IP is malicious using VirusTotal"""
    is_malicious, details = is_ip_malicious(ip_address)
    
    result = {
        "ip": ip_address,
        "is_malicious": is_malicious,
        "status": details.get("status", "UNKNOWN"),
        "details": details
    }
    
    return jsonify(result)

# NEW: Endpoint to clear the VirusTotal cache
@app.route("/clear-vt-cache", methods=["POST"])
@require_trusted_ip
def clear_vt_cache():
    """Clear the VirusTotal cache"""
    with data_lock:
        cache_size = len(vt_cache)
        vt_cache.clear()
        return jsonify({"status": "success", "message": f"Cleared VirusTotal cache ({cache_size} entries)"})

if __name__ == "__main__":
    logger.info("Starting security server with trusted IP management, malicious IP detection, and heavy request mitigation...")
    app.run(host="0.0.0.0", port=80)
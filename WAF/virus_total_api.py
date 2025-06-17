import requests
import re

def is_ip_malicious(ip_address, api_key="f46e41d8bbafc4d6a16baa759702f3473056ad64fbefdf1534d764b96f8566ca"):
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
            return True, details
        elif malicious_count == 1 or suspicious_count >= 2:
            details["status"] = "SUSPICIOUS"
            details["reason"] = f"Flagged suspicious by {suspicious_count} vendors, malicious by {malicious_count}"
            return False, details
        else:
            details["status"] = "SAFE"
            details["reason"] = "No significant threats detected"
            return False, details
            
    except Exception as e:
        return False, {"status": "ERROR", "reason": f"Error processing results: {str(e)}"}

def is_valid_ip(ip):
    """Validate IPv4 address format"""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))


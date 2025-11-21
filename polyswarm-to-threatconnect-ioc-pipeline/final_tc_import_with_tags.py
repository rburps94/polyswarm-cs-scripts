import requests
import json
import os
import hashlib
import hmac
import base64
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

# ✅ ThreatConnect API Configuration
TC_API_ACCESS_ID = "<TC_ID>"
TC_SECRET_KEY = "2EmnuTd..."
TC_API_BASE_URL = "https://partners.threatconnect.com"
TC_OWNER = "<OWNER_NAME>"

# ✅ Directory Path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def log_message(message):
    """Print messages with timestamps."""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    print(f"[{timestamp}] {message}")

def generate_hmac_signature(http_method, api_endpoint):
    """Generate HMAC signature for ThreatConnect API requests."""
    timestamp = str(int(time.time()))

    if not api_endpoint.startswith("/api"):
        api_endpoint = f"/api{api_endpoint}"

    signing_data = f"{api_endpoint}:{http_method}:{timestamp}"
    log_message(f"🔑 Signing Data (Pre-Hash): '{signing_data}'")

    signature = hmac.new(
        TC_SECRET_KEY.encode('utf-8'),
        signing_data.encode('utf-8'),
        hashlib.sha256
    ).digest()

    signature_b64 = base64.b64encode(signature).decode('utf-8')
    log_message(f"🔑 Generated HMAC Signature: {signature_b64}")

    return signature_b64, timestamp

def make_authenticated_request(http_method, endpoint, payload=None):
    """Make an authenticated request to ThreatConnect."""
    api_url = f"{TC_API_BASE_URL}{endpoint}"
    signature, timestamp = generate_hmac_signature(http_method, endpoint)

    headers = {
        "Authorization": f"TC {TC_API_ACCESS_ID}:{signature}",
        "Timestamp": timestamp,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "PostmanRuntime/7.43.0",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate, br"
    }

    if http_method == "POST":
        response = requests.post(api_url, headers=headers, json=payload)
    elif http_method == "GET":
        response = requests.get(api_url, headers=headers)

    log_message(f"🔍 Response Status: {response.status_code}")
    return response

def test_api_credentials():
    """Test API credentials before proceeding."""
    response = make_authenticated_request("GET", "/api/v3/security/owners")

    if response.status_code == 200:
        log_message("✅ API credentials are valid. Proceeding with execution.")
    else:
        log_message("❌ API Key is unauthorized or has insufficient permissions.")
        exit(1)

def find_latest_json():
    """Find the most recent JSON file in the directory."""
    json_files = [f for f in os.listdir(SCRIPT_DIR) if f.endswith(".json")]

    if not json_files:
        log_message("❌ No JSON file found. Exiting.")
        exit()

    latest_file = max(json_files, key=lambda x: os.path.getmtime(os.path.join(SCRIPT_DIR, x)))
    log_message(f"📂 Using JSON file: {latest_file}")
    return os.path.join(SCRIPT_DIR, latest_file)

def is_valid_ip(ip):
    """Check if an IP is valid and public (avoid private/local IPs)."""
    private_ranges = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."
    ]
    return not any(ip.startswith(prefix) for prefix in private_ranges)

def create_tc_indicator(indicator_type, value, tags):
    """Create an indicator in ThreatConnect with proper formatting."""
    url = "/api/v3/indicators"
    tags = [{"name": tag, "owner": TC_OWNER} for tag in tags if tag and tag.lower() != "unknown"]

    payload = {
        "ownerName": TC_OWNER,
        "tags": {"data": tags}
    }

    # ✅ Differentiating between IPs & URLs
    if indicator_type == "Address":
        if not is_valid_ip(value):
            log_message(f"⚠️ Skipping private/local IP: {value}")
            return
        payload["type"] = "Address"
        payload["ip"] = value.strip()
    elif indicator_type == "URL":
        payload["type"] = "URL"
        payload["text"] = value.strip()  # ✅ Using "text" for URLs
    else:
        log_message(f"⚠️ Skipping unknown indicator type: {indicator_type}")
        return

    log_message(f"📡 Sending {indicator_type} to ThreatConnect: {value}")

    response = make_authenticated_request("POST", url, payload=payload)

    if response.status_code == 201:
        log_message(f"✅ Created {indicator_type}: {value}")
    else:
        log_message(f"❌ Failed to create {indicator_type}: {value} | Error: {response.text}")

def process_iocs():
    """Read the latest JSON and create IOCs in ThreatConnect."""
    json_file = find_latest_json()

    try:
        with open(json_file, "r") as file:
            data = json.load(file)

        if not data:
            log_message("❌ JSON file contains no valid data. Exiting.")
            exit()
    except json.JSONDecodeError:
        log_message("❌ JSON file is corrupted or improperly formatted. Exiting.")
        exit()

    for entry in data:
        tags = list(filter(None, [
            entry.get("malware_family", ""), 
            entry.get("hash", ""), 
            entry.get("extension", ""), 
            entry.get("pe_type", "")
        ] + entry.get("labels", []) + entry.get("ttps", [])))

        for ip in entry.get("ips", []):
            if ip.startswith("http"):  # ✅ If it looks like a URL, classify it correctly
                create_tc_indicator("URL", ip, tags)
            else:
                create_tc_indicator("Address", ip, tags)

    for url in entry.get("urls", []):
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"  # ✅ Assume HTTP if missing a scheme

        parsed_url = urlparse(url)
        if parsed_url.scheme and parsed_url.netloc:
            create_tc_indicator("URL", url, tags)
        else:
            log_message(f"⚠️ Skipping invalid URL: {url}")


if __name__ == "__main__":
    log_message("🚀 Starting ThreatConnect IOC Import...")
    test_api_credentials()
    process_iocs()
    log_message("✅ IOC Import Complete.")

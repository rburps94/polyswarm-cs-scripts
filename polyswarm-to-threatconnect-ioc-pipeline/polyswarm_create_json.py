import requests
import json
import os
from datetime import datetime, timezone

# ✅ Constants
API_KEY = "<PS_API_KEY>"
BASE_SEARCH_URL = "https://api.polyswarm.network/v3/search/metadata/query"
IOC_LOOKUP_URL = "https://api.polyswarm.network/v3/ioc/sha256/"
QUERY = (
    "polyunite.malware_family:(Atomic OR Cthulhu OR Banshee OR Cerber OR Play OR BlackSuit OR BlackMatter OR REvil OR Akira "
    "OR LockBit OR HellDown OR RansomHub OR TargetCompany OR Cl0p OR BlackBasta OR NotLockBit OR SystemBC OR RustDoor "
    "OR HZRAT OR Bootkitty OR Androxgh0st OR Ebury OR Mirai OR Perfectl OR CobaltStrike) "
    "AND scan.latest_scan.polyscore:>=0.95 AND artifact.created:>now-1d"
)
HEADERS = {"Authorization": API_KEY}

# ✅ Directory Path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "script_run_log.txt")

def log_message(message):
    """Print messages with timestamps."""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    
    # Append only relevant log entries to the log file
    if "Total Hashes Found" in message or "Hashes Skipped due to No IOCs" in message or "Total Unique IOCs Retrieved" in message or "Unique IPs" in message or "Unique URLs" in message or "Unique TTPs" in message:
        with open(LOG_FILE, "a") as log:
            log.write(log_entry + "\n")

def delete_existing_json():
    """Delete any existing JSON file in the directory."""
    for file in os.listdir(SCRIPT_DIR):
        if file.endswith(".json"):
            os.remove(os.path.join(SCRIPT_DIR, file))
            log_message(f"🗑 Deleted existing JSON file: {file}")

def fetch_data(url, retries=3, backoff_factor=2):
    """Fetch data from the PolySwarm API with retries on failure."""
    attempt = 0
    while attempt < retries:
        attempt += 1
        try:
            response = requests.get(url, headers=HEADERS)
            
            # ✅ Handle Empty Response
            if response.status_code == 204 or not response.text.strip():
                return None  # Return None if no results

            response.raise_for_status()  # Raises HTTPError for 4xx, 5xx responses
            return response.json()

        except requests.exceptions.HTTPError as e:
            log_message(f"❌ HTTP Error: {e}")
            wait_time = backoff_factor ** (attempt - 1) # Exponential backoff calculation
            log_message(f"Retrying in {wait_time:.2f} seconds (attempt {attempt}/{retries}).")
            time.sleep(wait_time)
            break

        except requests.exceptions.RequestException as e:
            log_message(f"❌ Network Error: {e}")
            wait_time = backoff_factor ** (attempt - 1) # Exponential backoff calculation
            log_message(f"Retrying in {wait_time:.2f} seconds (attempt {attempt}/{retries}).")
            time.sleep(wait_time)
            break

    return None

def extract_hashes(data):
    """Extract malware family names, hashes, and additional metadata from the API response."""
    if not data or "result" not in data:
        return []  # ✅ Return an empty list if no data found

    results = data["result"]
    extracted = []

    for item in results:
        malware_family = item.get("polyunite", {}).get("malware_family", "Unknown")
        hash_sha256 = item.get("artifact", {}).get("sha256", "Unknown")
        extension = item.get("extension", "Unknown")
        petype = item.get("exiftool", {}).get("petype", "Unknown")
        labels = item.get("polyunite", {}).get("labels", [])

        extracted.append({
            "malware_family": malware_family,
            "hash": hash_sha256,
            "extension": extension,
            "petype": petype,
            "labels": labels
        })

    log_message(f"✅ Found {len(extracted)} hashes, extracting IOCs and moving on to next set...")
    return extracted

def fetch_ioc_details(sha256):
    """Fetch IOC details for a given hash."""
    url = f"{IOC_LOOKUP_URL}{sha256}?community=default"
    data = fetch_data(url)

    if not data or "result" not in data:
        return None

    result = data["result"]
    return {
        "ips": result.get("ips", []),
        "urls": result.get("urls", []),
        "ttps": result.get("ttps", [])
    }

def save_results(extracted_data):
    """Save results to a JSON file if data exists."""
    if not extracted_data:
        log_message("⚠️ No IOCs found. Skipping JSON file creation.")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(SCRIPT_DIR, f"polyswarm_iocs_{timestamp}.json")

    with open(filename, "w") as f:
        json.dump(extracted_data, f, indent=4)

    log_message(f"📁 IOC Results saved to {filename}")

def main():
    """Fetch hashes, retrieve IOC data, and save results."""
    log_message("🚀 Fetching malware hashes from PolySwarm API...")

    # ✅ Delete any existing JSON file first
    delete_existing_json()

    all_extracted_data = []
    all_ips = set()
    all_urls = set()
    all_ttps = set()
    total_hashes = 0
    skipped_hashes = 0

    next_offset = None

    while True:
        url = f"{BASE_SEARCH_URL}?query={QUERY}"
        if next_offset:
            url += f"&offset={next_offset}"

        data = fetch_data(url)
        if not data:
            log_message("❌ No results found. Stopping execution.")
            break

        hashes = extract_hashes(data)
        total_hashes += len(hashes)

        if not hashes:
            log_message("⚠️ No malware samples found in the query results.")
            break

        for entry in hashes:
            hash_sha256 = entry["hash"]
            ioc_details = fetch_ioc_details(hash_sha256)

            if ioc_details and (ioc_details["ips"] or ioc_details["urls"] or ioc_details["ttps"]):
                entry.update(ioc_details)
                all_extracted_data.append(entry)

                all_ips.update(ioc_details["ips"])
                all_urls.update(ioc_details["urls"])
                all_ttps.update(ioc_details["ttps"])
            else:
                skipped_hashes += 1

        next_offset = data.get("offset")
        has_more = data.get("has_more", False)

        # log_message(f"🔄 Next offset: {next_offset} | More pages? {has_more}")

        if not has_more or not next_offset:
            break

    save_results(all_extracted_data)

    log_message(f"✅ Total Hashes Found matching Malware Families: {total_hashes}")
    log_message(f"---")
    log_message(f"⚠️ Hashes (skipped) with no IOCs: {skipped_hashes}")
    log_message(f"✅ Hashes with IOCs: {len(all_extracted_data)}")
    log_message(f"---")
    log_message(f"🔹 Unique IPs: {len(all_ips)}")
    log_message(f"🔹 Unique URLs: {len(all_urls)}")
    log_message(f"🔹 Unique TTPs: {len(all_ttps)}")

if __name__ == "__main__":
    main()

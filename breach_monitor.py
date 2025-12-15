# Breached Creds Monitor v1.0

#!/usr/bin/env python3
import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List
import requests
from dotenv import load_dotenv

load_dotenv()

# Create a .env file with these values populated
DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")

# Folder to store snapshot data
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

# ================================
# CONFIG: assets to monitor
# type determines query payload
# ================================
ASSETS = [
    {"key": "example_domain", "type": "domain", "value": "example.com"},
    {"key": "example_email", "type": "email", "value": "admin@example.com"},
]


# ================================
# Teams Webhook Alert
# ================================
def send_teams_webhook(message: str):
    if not TEAMS_WEBHOOK_URL:
        print("TEAMS_WEBHOOK_URL not set. Skipping alert.")
        return

    try:
        payload = {"text": message}
        resp = requests.post(
            TEAMS_WEBHOOK_URL,
            json=payload,
            timeout=10
        )
        resp.raise_for_status()
        print("[+] Sent Teams alert")
    except Exception as e:
        print(f"[ERROR] Teams webhook failed: {e}")


# ================================
# Dehashed Query
# ================================
def query_dehashed(asset_type: str, asset_value: str) -> List[Dict[str, Any]]:
    if asset_type not in ("domain", "email"):
        raise ValueError(f"Unsupported asset type: {asset_type}")

    # Construct query
    search_query = f"{asset_type}:{asset_value}"

    body = {
        "query": search_query,
        "page": 1,
        "size": 10000,
        "regex": False,
        "wildcard": True,
        "de_dupe": False,
    }

    headers = {
        "Accept": "application/json",
        "Dehashed-Api-Key": f"{DEHASHED_API_KEY}",
    }

    print(f"[+] Querying Dehashed for: {search_query}")

    resp = requests.post(
        "https://api.dehashed.com/v2/search",
        json=body,
        headers=headers,
        timeout=30
    )

    resp.raise_for_status()

    data = resp.json()
    return data.get("entries", [])


# ================================
# File Helpers
# ================================
def get_snapshot_path(asset_key: str) -> Path:
    return DATA_DIR / f"{asset_key}.json"


def load_previous_snapshot(asset_key: str) -> List[Dict[str, Any]]:
    path = get_snapshot_path(asset_key)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_snapshot(asset_key: str, entries: List[Dict[str, Any]]):
    path = get_snapshot_path(asset_key)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


# ================================
# Detect new breached entries
# ================================
def diff_entries(old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Compares entries using a stable hash of each entry to detect newly added items.
    """
    def entry_hash(entry: Dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

    old_set = {entry_hash(e) for e in old}
    new_set = {entry_hash(e) for e in new}

    added_hashes = new_set - old_set

    return [e for e in new if entry_hash(e) in added_hashes]


# ================================
# Main Logic
# ================================
def run_monitor():
    for asset in ASSETS:
        asset_key = asset["key"]
        asset_type = asset["type"]
        asset_value = asset["value"]

        print(f"\n=== Checking asset: {asset_key} ({asset_type}: {asset_value}) ===")

        previous_entries = load_previous_snapshot(asset_key)
        new_entries = query_dehashed(asset_type, asset_value)

        if not previous_entries:
            print("[+] Initial run — saving baseline.")
            save_snapshot(asset_key, new_entries)
            continue

        additions = diff_entries(previous_entries, new_entries)

        if additions:
            print(f"[!] FOUND {len(additions)} NEW BREACHED RECORDS")

            for entry in additions:
                msg = (
                    f"ALERT — New breached credentials found for {asset_value}\n"
                    f"Type: {asset_type}\n"
                    f"Entry: {json.dumps(entry, indent=2)}"
                )
                send_teams_webhook(msg)

            # Only update snapshot if new items exist
            save_snapshot(asset_key, new_entries)
        else:
            print("[+] No new breached credentials found.")


if __name__ == "__main__":
    run_monitor()

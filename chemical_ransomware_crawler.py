#!/usr/bin/env python3
"""
Chemical Sector Ransomware Crawler
Secure API-key based implementation
"""

import requests
import csv
import os
from datetime import datetime

API_URL = "https://api.ransomware.live/v2/recentvictims"
API_KEY = os.getenv("RANSOMWARE_LIVE_API_KEY")  # pulled securely
KEYWORD = "chemical"
OUTPUT_DIR = "output"

if not API_KEY:
    raise RuntimeError("API key not found. Set RANSOMWARE_LIVE_API_KEY")

os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Accept": "application/json"
}

def fetch_data():
    response = requests.get(API_URL, headers=HEADERS, timeout=30)
    response.raise_for_status()
    return response.json()

def filter_chemical(data):
    results = []

    for item in data:
        if KEYWORD in str(item).lower():
            results.append({
                "date": item.get("discovered", "")[:10],
                "victim": item.get("victim", "N/A"),
                "country": item.get("country", "N/A"),
                "ransomware_group": item.get("group", "N/A")
            })

    return results

def save_csv(rows):
    if not rows:
        print("No chemical victims found")
        return

    filename = f"{OUTPUT_DIR}/chemical_ransomware_{datetime.utcnow().strftime('%Y-%m-%d')}.csv"

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["date", "victim", "country", "ransomware_group"]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} records")

def main():
    data = fetch_data()
    filtered = filter_chemical(data)
    save_csv(filtered)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
GTI Enterprise Submission Hunter — Audit your own VirusTotal submission
history, extract file hashes, and verify data exclusivity.

Queries the /intelligence/search endpoint with ``submitter:me`` to find every
file uploaded by your API key in a given date range.  Paginates automatically,
checks exclusivity via unique_sources, and exports results to CSV.

Usage examples:
    python gti_hunter.py -k API_KEY -s 2025-01-01 -e 2025-06-30
    python gti_hunter.py -k API_KEY -s 2025-01-01 -e 2025-06-30 -o audit.csv
    python gti_hunter.py -k API_KEY -s 2025-01-01 -e 2025-06-30 -l 500

Requirements:
    - requests
    - tabulate
    - A GTI Enterprise / VirusTotal Intelligence API key
"""

import csv
import argparse
import sys
import time
import random
from datetime import datetime, date
from collections import Counter

try:
    import requests
except ImportError:
    sys.exit("[!] 'requests' library required.  Install with:  pip install requests")

try:
    from tabulate import tabulate
except ImportError:
    sys.exit("[!] 'tabulate' library required.  Install with:  pip install tabulate")

MAX_RETRIES = 5
RETRY_DELAY = 5  # seconds (initial; grows with exponential backoff)


def validate_date(date_str):
    """Validate that a string is a well-formed YYYY-MM-DD date."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return None


def format_epoch(epoch):
    """Convert a UNIX epoch to a readable YYYY-MM-DD HH:MM:SS string."""
    if epoch is None or epoch == 'N/A':
        return 'N/A'
    try:
        return datetime.utcfromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(epoch)


def api_get(url, headers, params, max_retries=MAX_RETRIES, retry_delay=RETRY_DELAY):
    """
    Make a GET request with retry logic and exponential backoff for
    transient errors (429 rate-limit, 5xx server errors).
    Returns parsed JSON on success, or None after exhausting retries.
    """
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=60)

            if response.status_code == 429 or response.status_code >= 500:
                wait = int(response.headers.get(
                    'Retry-After',
                    retry_delay * (2 ** attempt) + random.uniform(0, 1),
                ))
                print(f"[!] HTTP {response.status_code} — retrying in {wait}s "
                      f"(attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait)
                continue

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            wait = retry_delay * (2 ** attempt) + random.uniform(0, 1)
            print(f"[!] Request failed: {e} — retrying in {wait:.1f}s "
                  f"(attempt {attempt + 1}/{max_retries})...")
            time.sleep(wait)

    print("[-] API request failed after all retry attempts.")
    return None


def fetch_all_submissions(api_key, start_date, end_date, output_file, limit=None):
    """
    Queries VirusTotal Intelligence for files submitted by the specific API key.
    Paginates through all results and exports to CSV.
    """
    base_url = "https://www.virustotal.com/api/v3/intelligence/search"
    headers = {"x-apikey": api_key}
    
    # Query: 'submitter:me' restricts search to files uploaded by your API key
    # 'fs' filters by first submission date range
    query = f"submitter:me fs:{start_date}+ fs:{end_date}-"
    
    all_results = []
    type_counts = Counter()
    cursor = None
    
    print(f"[*] Querying GTI for: {query}")

    while True:
        # Determine how many to fetch in this batch (max 300)
        batch_limit = 300
        if limit and (limit - len(all_results)) < 300:
            batch_limit = limit - len(all_results)
            if batch_limit <= 0: break

        params = {'query': query, 'limit': batch_limit}
        if cursor:
            params['cursor'] = cursor

        data = api_get(base_url, headers, params)
        if data is None:
            print("[-] Stopping pagination due to persistent API errors.")
            break

        # Show total hits estimate from first response
        if not all_results:
            total_hits = data.get('meta', {}).get('total_hits', 'Unknown')
            print(f"[*] Approximately {total_hits} total files found.")

        files = data.get('data', [])
        if not files:
            break
        
        for f in files:
            attr = f.get('attributes', {})
            sha256 = f.get('id')
            f_type = attr.get('type_description', 'N/A')
            unique_src = attr.get('unique_sources', 0)

            # Verification Logic: 
            # If unique_sources is 1, you are the ONLY person who has submitted this file.
            is_exclusive = "YES" if unique_src == 1 else "NO"

            all_results.append({
                "sha256": sha256,
                "md5": attr.get('md5', 'N/A'),
                "filename": attr.get('meaningful_name', 'N/A'),
                "type": f_type,
                "exclusive_to_me": is_exclusive,
                "unique_sources": unique_src,
                "total_submissions": attr.get('times_submitted', 0),
                "submission_date": format_epoch(attr.get('first_submission_date'))
            })
            type_counts[f_type] += 1

        print(f"[+] Downloaded {len(all_results)} records...")

        # Handle Pagination
        cursor = data.get('meta', {}).get('cursor')
        if not cursor:
            break

    # Save to CSV
    if all_results:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)
        return all_results, type_counts
    return None, None

def main():
    parser = argparse.ArgumentParser(description="GTI Enterprise Submission Hunter")
    parser.add_argument("-k", "--key", required=True, help="Your VirusTotal/GTI API Key")
    parser.add_argument("-s", "--start", required=True, help="Start Date (YYYY-MM-DD)")
    parser.add_argument("-e", "--end", required=True, help="End Date (YYYY-MM-DD)")
    parser.add_argument("-o", "--output", default="my_submissions.csv", help="Output CSV file name")
    parser.add_argument("-l", "--limit", type=int, help="Optional: Cap total results")

    args = parser.parse_args()

    if validate_date(args.start) is None:
        print(f"[-] Invalid start date '{args.start}'. Expected format: YYYY-MM-DD")
        sys.exit(1)
    if validate_date(args.end) is None:
        print(f"[-] Invalid end date '{args.end}'. Expected format: YYYY-MM-DD")
        sys.exit(1)
    if validate_date(args.start) > validate_date(args.end):
        print(f"[-] Start date '{args.start}' is after end date '{args.end}'.")
        sys.exit(1)

    results, type_counts = fetch_all_submissions(args.key, args.start, args.end, args.output, args.limit)

    if results:
        # 1. Print a preview of the data (Top 10)
        print("\n### DATA PREVIEW (Top 10) ###")
        print(tabulate(results[:10], headers="keys", tablefmt="fancy_grid"))

        # 2. Print Summary Table
        print("\n### SUBMISSION SUMMARY BY TYPE ###")
        summary_data = [[f_type, count] for f_type, count in type_counts.items()]
        print(tabulate(summary_data, headers=["File Type", "Count"], tablefmt="grid"))
        
        # 3. Print Grand Totals
        exclusive_total = sum(1 for r in results if r['exclusive_to_me'] == "YES")
        print(f"\n[!] Exclusive Files (Only you submitted): {exclusive_total}")
        print(f"[!] Grand Total Extracted: {len(results)}")
        print(f"[!] CSV File Saved: {args.output}\n")
    else:
        print("[-] No submissions found for this API key in that date range.")

if __name__ == "__main__":
    main()

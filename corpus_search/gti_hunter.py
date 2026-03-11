#!/usr/bin/env python3
"""
GTI Enterprise Submission Hunter — Audit your organization's VirusTotal
public corpus submissions with per-submitter attribution via source_key.

Workflow:
  1. Queries /intelligence/search with submitter:me + fs: date range to
     get all files submitted by anyone in your VT group.
  2. For each file, fetches /files/{hash}/submissions to retrieve the
     source_key (unique per-API-key identifier) for every submission.
  3. Exports all results to CSV with submitter source_key attribution.
  4. Optionally filters to a specific source_key with --source-key.

Usage examples:
    # Discover your API key's source_key
    python gti_hunter.py -k API_KEY --discover-key

    # All group submissions in date range
    python gti_hunter.py -k API_KEY -s 2025-01-01 -e 2025-06-30

    # Filter to a specific submitter's source_key
    python gti_hunter.py -k API_KEY -s 2025-01-01 -e 2025-06-30 --source-key 324a3038

    # Only exclusive files (unique_sources == 1)
    python gti_hunter.py -k API_KEY -s 2025-01-01 -e 2025-06-30 -x

Requirements:
    - requests
    - tabulate
    - A GTI Enterprise / VirusTotal Intelligence API key
"""

import csv
import hashlib
import argparse
import sys
import time
import random
import tempfile
import os
from datetime import datetime, timezone
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

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
VT_BASE = "https://www.virustotal.com/api/v3"


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
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(epoch)


def api_get(url, headers, params, max_retries=MAX_RETRIES, retry_delay=RETRY_DELAY):
    """GET request with retry logic and exponential backoff."""
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

            if 400 <= response.status_code < 500:
                print(f"[-] HTTP {response.status_code}: {response.text[:200]}")
                return None

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            wait = retry_delay * (2 ** attempt) + random.uniform(0, 1)
            print(f"[!] Request failed: {e} — retrying in {wait:.1f}s "
                  f"(attempt {attempt + 1}/{max_retries})...")
            time.sleep(wait)

    print("[-] API request failed after all retry attempts.")
    return None


def resolve_user_and_group(api_key):
    """
    Resolve user ID, group ID, and group source_keys for the given API key.
    Returns (user_id, group_id, set_of_group_source_keys).
    """
    headers = {"x-apikey": api_key}

    # Get user info
    data = api_get(f"{VT_BASE}/users/{api_key}", headers, params={})
    if data is None:
        return None, None, set()

    user_id = data.get('data', {}).get('id', 'unknown')
    attr = data.get('data', {}).get('attributes', {})
    email = attr.get('email', 'N/A')
    print(f"[*] User: {user_id}  |  Email: {email}")

    # Get group
    grp_data = api_get(f"{VT_BASE}/users/{user_id}/groups", headers, params={})
    group_id = None
    if grp_data and grp_data.get('data'):
        group_id = grp_data['data'][0].get('id')
        org = grp_data['data'][0].get('attributes', {}).get('organization', '')
        print(f"[*] Group: {group_id}  |  Org: {org}")

    return user_id, group_id, set()



def get_file_submissions(api_key, sha256, target_source_key=None):
    """
    Fetch submissions for a given file hash.
    If target_source_key is provided, paginates until that key is found
    or all submissions are exhausted. Otherwise returns first page only.
    """
    headers = {"x-apikey": api_key}
    all_subs = []
    cursor = None

    while True:
        params = {"limit": 40}
        if cursor:
            params['cursor'] = cursor
        data = api_get(f"{VT_BASE}/files/{sha256}/submissions", headers, params)
        if data is None:
            break

        page_subs = [s.get('attributes', {}) for s in data.get('data', [])]
        if not page_subs:
            break
        all_subs.extend(page_subs)

        # If we're looking for a specific key and found it, stop early
        if target_source_key:
            if any(s.get('source_key') == target_source_key for s in page_subs):
                break

        # If no target key, just return first page (original behavior)
        if not target_source_key:
            break

        cursor = data.get('meta', {}).get('cursor')
        if not cursor:
            break

    return all_subs


def discover_my_source_key(api_key):
    """
    Discover this API key's source_key by submitting a unique probe file,
    then looking up its submissions to find the source_key.
    Returns (source_key, submission_details) or (None, None).
    """
    headers = {"x-apikey": api_key}

    # Create a unique probe file
    probe_content = f"source_key_probe_{api_key[:8]}_{int(time.time())}_{random.randint(0, 999999)}"
    probe_bytes = probe_content.encode('utf-8')
    probe_hash = hashlib.sha256(probe_bytes).hexdigest()

    print(f"[*] Submitting probe file to discover your source_key...")
    print(f"[*] Probe SHA256: {probe_hash}")

    # Submit the probe file
    try:
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as tmp:
            tmp.write(probe_bytes)
            tmp_path = tmp.name

        resp = requests.post(
            f"{VT_BASE}/files",
            headers=headers,
            files={"file": ("source_key_probe.txt", open(tmp_path, 'rb'))},
            timeout=60,
        )
        os.unlink(tmp_path)

        if resp.status_code != 200:
            print(f"[-] Probe submission failed: HTTP {resp.status_code}")
            return None, None

        print(f"[+] Probe submitted. Waiting for indexing...")

    except requests.exceptions.RequestException as e:
        print(f"[-] Probe submission failed: {e}")
        return None, None

    # Wait for VT to index, then fetch submissions
    for wait_secs in [5, 5, 10, 15]:
        time.sleep(wait_secs)
        data = api_get(f"{VT_BASE}/files/{probe_hash}/submissions",
                       headers, params={"limit": 10})
        if data and data.get('data'):
            sub = data['data'][0].get('attributes', {})
            source_key = sub.get('source_key')
            if source_key:
                return source_key, sub
        print(f"[*] Not indexed yet, waiting {wait_secs}s more...")

    print("[-] Could not retrieve source_key — probe file may not be indexed yet.")
    print(f"[*] Try again in a minute, or look up the probe hash manually:")
    print(f"    {probe_hash}")
    return None, None


def discover_group_source_keys(api_key, group_id):
    """
    Get all users in the group. We can't directly get their source_keys,
    but we collect user IDs for reference.
    Returns a list of user ID strings.
    """
    if not group_id:
        return []
    headers = {"x-apikey": api_key}
    users = []
    cursor = None
    while True:
        params = {"limit": 40}
        if cursor:
            params['cursor'] = cursor
        data = api_get(f"{VT_BASE}/groups/{group_id}/users", headers, params)
        if data is None:
            break
        for u in data.get('data', []):
            users.append(u.get('id', '?'))
        cursor = data.get('meta', {}).get('cursor')
        if not cursor:
            break
    return users


def fetch_and_audit_submissions(api_key, start_date, end_date, output_file,
                                 limit=None, exclusive_only=False, filter_source_key=None):
    """
    1. Query intelligence/search with submitter:me + fs: date range to get
       all files submitted by anyone in the group.
    2. For each file, fetch /files/{hash}/submissions to get source_key
       attribution for every submitter.
    3. If --source-key is provided, only include files from that submitter.
       Otherwise include all files with their submitter source_keys.
    """
    headers = {"x-apikey": api_key}
    search_url = f"{VT_BASE}/intelligence/search"

    # submitter:me scopes to the group/org level — returns files submitted by
    # anyone in your VT group, not the entire global corpus.
    query = f"submitter:me fs:{start_date}+ fs:{end_date}-"
    all_results = []
    type_counts = Counter()
    source_key_counts = Counter()
    cursor = None
    total_checked = 0

    print(f"[*] Searching group submissions: {query}")
    if filter_source_key:
        print(f"[*] Filtering to source_key: {filter_source_key}")
    else:
        print(f"[*] Showing ALL group submissions with source_key attribution")

    while True:
        batch_limit = 300
        if limit and (limit - len(all_results)) < 300:
            batch_limit = limit - len(all_results)
            if batch_limit <= 0:
                break

        params = {'query': query, 'limit': batch_limit}
        if cursor:
            params['cursor'] = cursor

        data = api_get(search_url, headers, params)
        if data is None:
            print("[-] Stopping pagination due to persistent API errors.")
            break

        if total_checked == 0:
            total_hits = data.get('meta', {}).get('total_hits', 'Unknown')
            print(f"[*] Approximately {total_hits} files in date range...")

        files = data.get('data', [])
        if not files:
            break

        # Pre-filter files before expensive submission lookups
        candidates = []
        for f in files:
            attr = f.get('attributes', {})
            sha256 = f.get('id')
            total_checked += 1

            unique_src = attr.get('unique_sources', 0)
            if exclusive_only and unique_src != 1:
                continue

            candidates.append((sha256, attr))

        # Fetch submissions concurrently for candidates
        submission_map = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(get_file_submissions, api_key, sha256, filter_source_key): sha256
                for sha256, _ in candidates
            }
            for future in as_completed(futures):
                sha256 = futures[future]
                submission_map[sha256] = future.result()

        for sha256, attr in candidates:
            subs = submission_map.get(sha256, [])

            # Collect all unique source_keys for this file
            file_source_keys = set()
            earliest_sub = None
            matched_sub = None
            for s in subs:
                sk = s.get('source_key', 'unknown')
                file_source_keys.add(sk)
                if earliest_sub is None or s.get('date', 0) < earliest_sub.get('date', 0):
                    earliest_sub = s
                if filter_source_key and sk == filter_source_key:
                    matched_sub = s

            # If filtering by source_key, skip files not from that submitter
            if filter_source_key and filter_source_key not in file_source_keys:
                continue

            # Use the matched submission if filtering, otherwise the earliest
            display_sub = matched_sub or earliest_sub or {}

            f_type = attr.get('type_description', 'N/A')
            unique_src = attr.get('unique_sources', 0)
            is_exclusive = "YES" if unique_src == 1 else "NO"

            all_results.append({
                "sha256": sha256,
                "md5": attr.get('md5', 'N/A'),
                "filename": attr.get('meaningful_name', 'N/A'),
                "type": f_type,
                "type_extension": attr.get('type_extension', 'N/A'),
                "downloadable": attr.get('downloadable', False),
                "exclusive_to_me": is_exclusive,
                "unique_sources": unique_src,
                "total_submissions": attr.get('times_submitted', 0),
                "submission_date": format_epoch(display_sub.get('date')),
                "first_submission_date": format_epoch(attr.get('first_submission_date')),
                "source_key": display_sub.get('source_key', 'N/A'),
                "all_source_keys": ", ".join(sorted(file_source_keys)),
                "submission_interface": display_sub.get('interface', 'N/A'),
            })
            type_counts[f_type] += 1
            for sk in file_source_keys:
                source_key_counts[sk] += 1

            if limit and len(all_results) >= limit:
                break

        print(f"[+] Checked {total_checked} files, {len(all_results)} matched...")

        if limit and len(all_results) >= limit:
            break

        cursor = data.get('meta', {}).get('cursor')
        if not cursor:
            break

    # Save to CSV
    if all_results:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)
        return all_results, type_counts, source_key_counts
    return None, None, None


def main():
    parser = argparse.ArgumentParser(
        description="GTI Enterprise Submission Hunter — Audit group corpus submissions with submitter attribution")
    parser.add_argument("-k", "--key", required=True, help="Your VirusTotal/GTI API Key")
    parser.add_argument("-s", "--start", default=None, help="Start Date (YYYY-MM-DD)")
    parser.add_argument("-e", "--end", default=None, help="End Date (YYYY-MM-DD)")
    parser.add_argument("-o", "--output", default="my_submissions.csv", help="Output CSV file name")
    parser.add_argument("-l", "--limit", type=int, help="Cap total matched results")
    parser.add_argument("-x", "--exclusive", action="store_true",
                        help="Only return files where unique_sources == 1")
    parser.add_argument("--source-key", default=None,
                        help="Filter results to a specific submitter source_key "
                             "(omit to show all group submissions)")
    parser.add_argument("--discover-key", action="store_true",
                        help="Discover your API key's source_key by submitting a probe file, "
                             "then display your key info and exit")

    args = parser.parse_args()

    # --discover-key mode: find and display the source_key for this API key
    if args.discover_key:
        print("### SOURCE_KEY DISCOVERY ###\n")

        # Resolve user/group info
        user_id, group_id, _ = resolve_user_and_group(args.key)
        group_users = []
        if group_id:
            group_users = discover_group_source_keys(args.key, group_id)

        # Discover source_key via probe submission
        print()
        source_key, sub_details = discover_my_source_key(args.key)

        if source_key:
            print(f"\n### YOUR API KEY INFO ###")
            info = [
                ["source_key", source_key],
                ["user_id", user_id or "N/A"],
                ["group", group_id or "N/A"],
                ["group_users", len(group_users) if group_users else "N/A"],
                ["submission_interface", sub_details.get('interface', 'N/A')],
                ["submission_country", sub_details.get('country', 'N/A')],
                ["submission_city", sub_details.get('city', 'N/A')],
                ["api_key_prefix", args.key[:8] + "..."],
            ]
            print(tabulate(info, headers=["Field", "Value"], tablefmt="grid"))
            print(f"\n[+] Use this source_key to filter submissions:")
            print(f"    python gti_hunter.py -k YOUR_KEY -s START -e END --source-key {source_key}\n")
        else:
            print("\n[-] Discovery failed. See messages above.")
        return

    # Normal audit mode — require date args
    if not args.start or not args.end:
        parser.error("-s/--start and -e/--end are required (unless using --discover-key)")

    if validate_date(args.start) is None:
        print(f"[-] Invalid start date '{args.start}'. Expected format: YYYY-MM-DD")
        sys.exit(1)
    if validate_date(args.end) is None:
        print(f"[-] Invalid end date '{args.end}'. Expected format: YYYY-MM-DD")
        sys.exit(1)
    if validate_date(args.start) > validate_date(args.end):
        print(f"[-] Start date '{args.start}' is after end date '{args.end}'.")
        sys.exit(1)

    # Step 1: Resolve user/group info
    user_id, group_id, _ = resolve_user_and_group(args.key)

    # Step 2: Discover group members
    if group_id:
        group_users = discover_group_source_keys(args.key, group_id)
        print(f"[*] Group '{group_id}' has {len(group_users)} users.")

    # Step 3: Search and audit all group submissions
    print()
    results, type_counts, source_key_counts = fetch_and_audit_submissions(
        args.key, args.start, args.end, args.output,
        args.limit, args.exclusive, args.source_key
    )

    if results:
        print(f"\n### DATA PREVIEW (Top 10) ###")
        print(tabulate(results[:10], headers="keys", tablefmt="fancy_grid"))

        print(f"\n### SUBMISSION SUMMARY BY FILE TYPE ###")
        summary_data = [[f_type, count] for f_type, count in type_counts.items()]
        print(tabulate(summary_data, headers=["File Type", "Count"], tablefmt="grid"))

        print(f"\n### TOP 10 SUBMITTERS BY SOURCE_KEY ###")
        sk_data = [[sk, count] for sk, count in source_key_counts.most_common(10)]
        print(tabulate(sk_data, headers=["source_key", "Files"], tablefmt="grid"))

        exclusive_total = sum(1 for r in results if r['exclusive_to_me'] == "YES")
        print(f"\n[!] Exclusive Files (unique_sources == 1): {exclusive_total}")
        print(f"[!] Grand Total: {len(results)}")
        print(f"[!] Unique Submitters (source_keys): {len(source_key_counts)}")
        print(f"[!] CSV File Saved: {args.output}\n")
    else:
        print("[-] No submissions found for your group in that date range.")


if __name__ == "__main__":
    main()

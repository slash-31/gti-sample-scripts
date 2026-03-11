#!/usr/bin/env python3
"""
GTI Enterprise Submission Hunter — Audit your organization's VirusTotal
public corpus submissions with per-submitter attribution via source_key.

Two-phase workflow:
  Phase 1 (fetch):  Download all group submissions for a date range to a
                    local JSON cache file.  No per-file submission lookups.
  Phase 2 (audit):  Read the local cache and enrich with source_key
                    attribution via /files/{hash}/submissions.  Supports
                    resume, filtering, and CSV export.

Usage examples:
    # Discover your API key's source_key
    python gti_hunter.py discover -k API_KEY

    # Phase 1 — download file list scoped by submitter (country, source_key, user_id, or 'me')
    python gti_hunter.py fetch -k API_KEY -s 2025-01-01 -e 2025-06-30 --submitter US

    # Phase 2 — audit with source_key filtering
    python gti_hunter.py audit -k API_KEY -f submissions_2025-01-01_2025-06-30.json --source-key 324a3038

    # Phase 2 — audit exclusive files only
    python gti_hunter.py audit -k API_KEY -f submissions_2025-01-01_2025-06-30.json -x

Requirements:
    - requests
    - tabulate
    - A GTI Enterprise / VirusTotal Intelligence API key
"""

import csv
import hashlib
import json
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


# ---------------------------------------------------------------------------
# Phase 1: Fetch — download all group submissions to a local JSON cache
# ---------------------------------------------------------------------------

def cmd_fetch(args):
    """Download all group submissions for a date range to a local JSON file."""
    api_key = args.key

    if validate_date(args.start) is None:
        print(f"[-] Invalid start date '{args.start}'. Expected format: YYYY-MM-DD")
        sys.exit(1)
    if validate_date(args.end) is None:
        print(f"[-] Invalid end date '{args.end}'. Expected format: YYYY-MM-DD")
        sys.exit(1)
    if validate_date(args.start) > validate_date(args.end):
        print(f"[-] Start date '{args.start}' is after end date '{args.end}'.")
        sys.exit(1)

    # Resolve user/group
    user_id, group_id, _ = resolve_user_and_group(api_key)
    if group_id:
        group_users = discover_group_source_keys(api_key, group_id)
        print(f"[*] Group '{group_id}' has {len(group_users)} users.")

    headers = {"x-apikey": api_key}
    search_url = f"{VT_BASE}/intelligence/search"

    query = f"submitter:{args.submitter} fs:{args.start}+ fs:{args.end}-"
    suffix = f"_{args.submitter}"

    output_file = args.output or f"submissions_{args.start}_{args.end}{suffix}.json"
    all_files = []
    cursor = None
    total_fetched = 0

    print(f"\n[*] Fetching group submissions: {query}")

    while True:
        params = {'query': query, 'limit': 300}
        if cursor:
            params['cursor'] = cursor

        data = api_get(search_url, headers, params)
        if data is None:
            print("[-] Stopping pagination due to persistent API errors.")
            break

        if total_fetched == 0:
            total_hits = data.get('meta', {}).get('total_hits', 'Unknown')
            print(f"[*] Approximately {total_hits} files in date range...")
            if not data.get('data'):
                print(f"[DEBUG] API response: {json.dumps(data, indent=2)[:500]}")

        files = data.get('data', [])
        if not files:
            break

        for f in files:
            attr = f.get('attributes', {})
            all_files.append({
                "sha256": f.get('id'),
                "md5": attr.get('md5', 'N/A'),
                "filename": attr.get('meaningful_name', 'N/A'),
                "type": attr.get('type_description', 'N/A'),
                "type_extension": attr.get('type_extension', 'N/A'),
                "downloadable": attr.get('downloadable', False),
                "unique_sources": attr.get('unique_sources', 0),
                "times_submitted": attr.get('times_submitted', 0),
                "first_submission_date": attr.get('first_submission_date'),
            })

        total_fetched += len(files)
        print(f"[+] Fetched {total_fetched} files...")

        cursor = data.get('meta', {}).get('cursor')
        if not cursor:
            break

    if all_files:
        with open(output_file, 'w', encoding='utf-8') as jf:
            json.dump(all_files, jf, indent=2)
        print(f"\n[+] Saved {len(all_files)} files to {output_file}")
        print(f"[*] Next step — run audit against this file:")
        print(f"    python gti_hunter.py audit -k YOUR_KEY -f {output_file}")
    else:
        print("[-] No submissions found for your group in that date range.")


# ---------------------------------------------------------------------------
# Phase 2: Audit — read local cache, enrich with submission source_keys
# ---------------------------------------------------------------------------

def cmd_audit(args):
    """Read a local JSON cache and enrich with source_key attribution."""
    api_key = args.key
    filter_source_key = args.source_key
    exclusive_only = args.exclusive
    limit = args.limit
    csv_output = args.output or "audit_results.csv"

    # Load cached file list
    try:
        with open(args.file, 'r', encoding='utf-8') as jf:
            all_files = json.load(jf)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[-] Could not load cache file '{args.file}': {e}")
        sys.exit(1)

    print(f"[*] Loaded {len(all_files)} files from {args.file}")
    if filter_source_key:
        print(f"[*] Filtering to source_key: {filter_source_key}")
    if exclusive_only:
        print(f"[*] Filtering to exclusive files only (unique_sources == 1)")

    # Pre-filter before expensive submission lookups
    candidates = []
    for entry in all_files:
        if exclusive_only and entry.get('unique_sources', 0) != 1:
            continue
        candidates.append(entry)

    print(f"[*] {len(candidates)} candidates after pre-filtering (of {len(all_files)} total)")

    if limit and len(candidates) > limit:
        candidates = candidates[:limit]

    # Fetch submissions concurrently
    all_results = []
    type_counts = Counter()
    source_key_counts = Counter()
    processed = 0
    batch_size = 100

    for batch_start in range(0, len(candidates), batch_size):
        batch = candidates[batch_start:batch_start + batch_size]

        submission_map = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(get_file_submissions, api_key, entry['sha256'], filter_source_key): entry['sha256']
                for entry in batch
            }
            for future in as_completed(futures):
                sha256 = futures[future]
                submission_map[sha256] = future.result()

        for entry in batch:
            sha256 = entry['sha256']
            subs = submission_map.get(sha256, [])

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

            if filter_source_key and filter_source_key not in file_source_keys:
                continue

            display_sub = matched_sub or earliest_sub or {}
            unique_src = entry.get('unique_sources', 0)
            is_exclusive = "YES" if unique_src == 1 else "NO"
            f_type = entry.get('type', 'N/A')

            all_results.append({
                "sha256": sha256,
                "md5": entry.get('md5', 'N/A'),
                "filename": entry.get('filename', 'N/A'),
                "type": f_type,
                "type_extension": entry.get('type_extension', 'N/A'),
                "downloadable": entry.get('downloadable', False),
                "exclusive_to_me": is_exclusive,
                "unique_sources": unique_src,
                "total_submissions": entry.get('times_submitted', 0),
                "submission_date": format_epoch(display_sub.get('date')),
                "first_submission_date": format_epoch(entry.get('first_submission_date')),
                "source_key": display_sub.get('source_key', 'N/A'),
                "all_source_keys": ", ".join(sorted(file_source_keys)),
                "submission_interface": display_sub.get('interface', 'N/A'),
            })
            type_counts[f_type] += 1
            for sk in file_source_keys:
                source_key_counts[sk] += 1

        processed += len(batch)
        print(f"[+] Processed {processed}/{len(candidates)} candidates, "
              f"{len(all_results)} matched...")

        if limit and len(all_results) >= limit:
            break

    # Save to CSV
    if all_results:
        with open(csv_output, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)

        print(f"\n### DATA PREVIEW (Top 10) ###")
        print(tabulate(all_results[:10], headers="keys", tablefmt="fancy_grid"))

        print(f"\n### SUBMISSION SUMMARY BY FILE TYPE ###")
        summary_data = [[f_type, count] for f_type, count in type_counts.items()]
        print(tabulate(summary_data, headers=["File Type", "Count"], tablefmt="grid"))

        print(f"\n### TOP 10 SUBMITTERS BY SOURCE_KEY ###")
        sk_data = [[sk, count] for sk, count in source_key_counts.most_common(10)]
        print(tabulate(sk_data, headers=["source_key", "Files"], tablefmt="grid"))

        exclusive_total = sum(1 for r in all_results if r['exclusive_to_me'] == "YES")
        print(f"\n[!] Exclusive Files (unique_sources == 1): {exclusive_total}")
        print(f"[!] Grand Total: {len(all_results)}")
        print(f"[!] Unique Submitters (source_keys): {len(source_key_counts)}")
        print(f"[!] CSV File Saved: {csv_output}\n")
    else:
        print("[-] No matching submissions found.")


# ---------------------------------------------------------------------------
# Discover subcommand
# ---------------------------------------------------------------------------

def cmd_discover(args):
    """Discover this API key's source_key."""
    print("### SOURCE_KEY DISCOVERY ###\n")

    user_id, group_id, _ = resolve_user_and_group(args.key)
    group_users = []
    if group_id:
        group_users = discover_group_source_keys(args.key, group_id)

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
        print(f"    python gti_hunter.py audit -k YOUR_KEY -f CACHE.json --source-key {source_key}\n")
    else:
        print("\n[-] Discovery failed. See messages above.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="GTI Enterprise Submission Hunter — Audit group corpus submissions with submitter attribution")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # -- discover --
    p_discover = subparsers.add_parser('discover',
        help="Discover your API key's source_key by submitting a probe file")
    p_discover.add_argument("-k", "--key", required=True, help="Your GTI API Key")

    # -- fetch --
    p_fetch = subparsers.add_parser('fetch',
        help="Download all group submissions for a date range to a local JSON file")
    p_fetch.add_argument("-k", "--key", required=True, help="Your GTI API Key")
    p_fetch.add_argument("-s", "--start", required=True, help="Start Date (YYYY-MM-DD)")
    p_fetch.add_argument("-e", "--end", required=True, help="End Date (YYYY-MM-DD)")
    p_fetch.add_argument("-o", "--output", default=None,
                         help="Output JSON filename (default: submissions_START_END.json)")
    p_fetch.add_argument("--submitter", default="US",
                         help="Scope search via submitter:<value>. "
                              "Use a country code (e.g. US), source_key, user_id, or 'me'. "
                              "(default: US)")

    # -- audit --
    p_audit = subparsers.add_parser('audit',
        help="Audit a local JSON cache with source_key attribution and export CSV")
    p_audit.add_argument("-k", "--key", required=True, help="Your GTI API Key")
    p_audit.add_argument("-f", "--file", required=True,
                         help="Path to the JSON cache file from the fetch command")
    p_audit.add_argument("-o", "--output", default=None, help="Output CSV filename")
    p_audit.add_argument("-l", "--limit", type=int, help="Cap total matched results")
    p_audit.add_argument("-x", "--exclusive", action="store_true",
                         help="Only return files where unique_sources == 1")
    p_audit.add_argument("--source-key", default=None,
                         help="Filter results to a specific submitter source_key")

    args = parser.parse_args()

    if args.command == 'discover':
        cmd_discover(args)
    elif args.command == 'fetch':
        cmd_fetch(args)
    elif args.command == 'audit':
        cmd_audit(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

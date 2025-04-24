#!/usr/bin/env python3
"""
Google Threat Intelligence Interactive Vulnerability Explorer (Looping)

This script:
1. Asks for a Google Threat Intelligence API key (requires Enterprise/Enterprise+ for Vulnerabilities).
2. Fetches the top 10 Vulnerabilities added or updated in the last 24 hours from Google TI.
3. Presents the list to the user.
4. Allows the user to select a vulnerability.
5. Fetches detailed information for the chosen vulnerability from Google TI.
6. Displays the detailed information.
7. Asks the user to select another vulnerability from the list or type 'end' to quit.
8. Repeats steps 4-7 until the user quits.

Usage:
    python gti_interactive_vuln_explorer_loop.py

Requirements:
    - requests
    - tabulate
    - A Google Threat Intelligence API key with Enterprise or Enterprise Plus privileges.
"""

import requests
import json
import sys
import os
from datetime import datetime, timedelta, timezone
from tabulate import tabulate
import time
import random
import getpass  # For secure API key input
from requests.exceptions import RequestException
import urllib.parse # To encode filters
import textwrap # For formatting long descriptions

# --- Configuration ---
# API Endpoint remains VirusTotal, as it hosts the Google TI data via this API
API_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 30 # Seconds
MAX_RETRIES = 3
RETRY_DELAY = 5 # Seconds
VULN_LIST_LIMIT = 10 # Number of vulnerabilities to initially list

# --- API Request Function ---
def make_api_request(url, api_key, params=None, max_retries=MAX_RETRIES, retry_delay=RETRY_DELAY):
    """
    Makes an API request (to VirusTotal endpoint for Google TI data)
    with retry logic for transient errors.
    Returns JSON response or None on persistent error.
    """
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    attempt = 0
    last_exception = None

    while attempt < max_retries:
        try:
            response = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)

            if response.status_code == 429: # Rate limited
                 wait_time = int(response.headers.get('Retry-After', retry_delay * (2 ** attempt)))
                 print(f"  [!] Rate limited ({response.status_code}). Retrying in {wait_time} seconds...", file=sys.stderr)
                 time.sleep(wait_time + random.uniform(0, 1)) # Add jitter
                 attempt += 1
                 continue
            elif response.status_code == 401: # Unauthorized
                 print(f"  [!] ERROR: API Key invalid or expired ({response.status_code}).", file=sys.stderr)
                 return None # No point retrying
            elif response.status_code == 403: # Forbidden
                 print(f"  [!] ERROR: Insufficient privileges ({response.status_code}).", file=sys.stderr)
                 print(f"      Check if your API key has the required Google TI Enterprise/Enterprise+ license.", file=sys.stderr)
                 return None # No point retrying
            elif response.status_code >= 500: # Server error
                 print(f"  [!] Server error ({response.status_code}). Retrying...", file=sys.stderr)
                 time.sleep(retry_delay * (2 ** attempt) + random.uniform(0, 1))
                 attempt += 1
                 continue

            response.raise_for_status()
            return response.json()

        except RequestException as e:
            last_exception = e
            print(f"  [!] Request attempt {attempt + 1} failed: {e}. Retrying...", file=sys.stderr)
            time.sleep(retry_delay * (2 ** attempt) + random.uniform(0, 1))
            attempt += 1

    print(f"  [!] ERROR: API request failed after {max_retries} attempts. Last error: {last_exception}", file=sys.stderr)
    return None

# --- Function to fetch top vulnerabilities ---
def get_recent_vulnerabilities(api_key, limit=VULN_LIST_LIMIT):
    """Fetches the most recently updated/added vulnerabilities from Google TI."""
    print(f"[*] Fetching top {limit} Vulnerabilities modified/added in the last 24 hours from Google TI...")
    filters = "collection_type:vulnerability last_modification_date:1d+"
    order = "last_modification_date-"
    params = {
        'filter': filters,
        'order': order,
        'limit': limit
    }
    query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    url = f"{API_BASE_URL}/collections?{query_string}"
    response_data = make_api_request(url, api_key)
    if response_data and 'data' in response_data:
        print(f"[*] Found {len(response_data['data'])} vulnerability/vulnerabilities.")
        return response_data['data']
    else:
        return None

# --- Function to display vulnerability choices ---
def display_vulnerability_choices(vulnerabilities):
    """Displays a numbered list of vulnerabilities for user selection."""
    if not vulnerabilities:
        print("[!] No vulnerabilities to display.")
        return False
    current_time_utc = datetime.now(timezone.utc)
    print(f"\n--- Top {len(vulnerabilities)} Google TI Vulnerabilities (Updated/Added Last 24 Hours as of {current_time_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}) ---")
    table_data = []
    headers = ["#", "ID / Name", "Risk", "CVSSv3", "Last Modified (UTC)"]
    for i, vuln in enumerate(vulnerabilities):
        attributes = vuln.get('attributes', {})
        vuln_id = vuln.get('id', 'N/A')
        name = attributes.get('name', vuln_id)
        risk = attributes.get('risk_rating', 'N/A')
        cvss3_score = attributes.get('cvss_3x_base_score', 'N/A')
        last_mod_ts = attributes.get('last_modification_date')
        last_mod_str = datetime.fromtimestamp(last_mod_ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if last_mod_ts else 'N/A'
        table_data.append([i + 1, name, risk, cvss3_score, last_mod_str])
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    return True

# --- Function to fetch specific vulnerability details ---
def get_vulnerability_details(api_key, vuln_id):
    """Fetches detailed information for a specific vulnerability ID from Google TI."""
    print(f"\n[*] Fetching Google TI details for Vulnerability ID: {vuln_id}...")
    url = f"{API_BASE_URL}/collections/{vuln_id}"
    response_data = make_api_request(url, api_key)
    if response_data and 'data' in response_data:
        return response_data['data']
    else:
        print(f"[!] Failed to fetch details for {vuln_id}.")
        return None

# --- Function to display detailed vulnerability info ---
def display_vulnerability_details(vuln_data):
    """Displays detailed information about a single vulnerability."""
    if not vuln_data:
        print("[!] No detailed vulnerability data to display.")
        return
    attributes = vuln_data.get('attributes', {})
    vuln_id = vuln_data.get('id', 'N/A')
    name = attributes.get('name', vuln_id)
    print("\n" + "="*60)
    print(f" Google TI Vulnerability Details: {name}")
    print("="*60)
    print(f"  ID: {vuln_id}")
    print(f"  Risk Rating: {attributes.get('risk_rating', 'N/A')}")
    print(f"  Exploitation State: {attributes.get('exploitation_state', 'N/A')}")
    create_ts = attributes.get('creation_date')
    create_str = datetime.fromtimestamp(create_ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z') if create_ts else 'N/A'
    modify_ts = attributes.get('last_modification_date')
    modify_str = datetime.fromtimestamp(modify_ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z') if modify_ts else 'N/A'
    print(f"  Creation Date: {create_str}")
    print(f"  Last Modified: {modify_str}")
    print("\n  --- CVSS Scores ---")
    print(f"  CVSS v3.x Base Score: {attributes.get('cvss_3x_base_score', 'N/A')}")
    print(f"  CVSS v3.x Temporal Score: {attributes.get('cvss_3x_temporal_score', 'N/A')}")
    print(f"  CVSS v2.0 Base Score: {attributes.get('cvss_2x_base_score', 'N/A')}")
    print(f"  CVSS v2.0 Temporal Score: {attributes.get('cvss_2x_temporal_score', 'N/A')}")
    print("\n  --- Description ---")
    description = attributes.get('description', 'N/A')
    print(textwrap.fill(description, width=80, initial_indent="  ", subsequent_indent="  ") if description != 'N/A' else "  N/A")
    print("\n  --- Affected Products (Sample) ---")
    products = attributes.get('vulnerable_product_objects', [])
    if products:
        for prod in products[:5]:
             print(f"  - Vendor: {prod.get('vendor', '?')}, Product: {prod.get('product', '?')}, Version: {prod.get('version', '?')}")
        if len(products) > 5: print(f"  ... and {len(products) - 5} more.")
    else:
        vendor = attributes.get('vulnerable_vendor')
        product = attributes.get('vulnerable_product')
        print(f"  Vendor: {vendor or 'N/A'}, Product: {product or 'N/A'}" if vendor or product else "  No specific product information readily available in attributes.")
    print("\n  --- References ---")
    references = attributes.get('references', [])
    if references:
        for ref in references[:10]: print(f"  - {ref}")
        if len(references) > 10: print(f"  ... and {len(references) - 10} more.")
    else: print("  No references listed.")
    print("\n  --- Tags ---")
    tags = attributes.get('tags', [])
    print("  " + ", ".join(tags) if tags else "  No tags listed.")
    print("="*60)

# --- Main Execution Logic ---
def main():
    """Main function to run the interactive vulnerability explorer."""
    print("--- Google Threat Intelligence Interactive Vulnerability Explorer ---")
    print("[!] IMPORTANT: Requires Google Threat Intelligence Enterprise/Enterprise+ License.")
    print("-" * 60)

    api_key = None
    try:
        # Clarify key origin for user
        api_key = getpass.getpass("Please enter your Google Threat Intelligence (VirusTotal) API Key: ")
        if not api_key:
            print("[!] API Key cannot be empty. Exiting.")
            sys.exit(1)
    except EOFError:
         print("\n[!] Input cancelled. Exiting.")
         sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred reading the API key: {e}")
        sys.exit(1)

    # 1. Fetch top Vulnerabilities
    vulnerabilities = get_recent_vulnerabilities(api_key)

    # Handle fetch failure
    if vulnerabilities is None:
        print("[!] Could not retrieve Vulnerability list. Please check your API key and permissions.")
        sys.exit(1)

    # Handle case where no vulnerabilities are found
    if not vulnerabilities:
        print("[*] No Vulnerabilities found matching the criteria (updated/added in last 24 hours).")
        sys.exit(0)

    num_options = len(vulnerabilities)

    # 2. Present choices ONCE
    if not display_vulnerability_choices(vulnerabilities):
         print("[!] Failed to display vulnerability choices.")
         sys.exit(1)

    # --- Main Interactive Loop ---
    while True:
        # 3. Get user selection OR 'end' command
        prompt = f"\nEnter number (1-{num_options}) to view details, or type 'end' to quit: "
        try:
            user_input = input(prompt).strip()
            if user_input.lower() == 'end':
                break # Exit the loop

            # Try converting to number and validate
            choice_int = int(user_input)
            if 1 <= choice_int <= num_options:
                selected_index = choice_int - 1
            else:
                print(f"[!] Invalid choice. Please enter a number between 1 and {num_options} or 'end'.")
                continue # Ask again

        except ValueError:
            print("[!] Invalid input. Please enter a number or 'end'.")
            continue # Ask again
        except EOFError:
             print("\n[!] Input cancelled. Exiting.")
             sys.exit(1) # Exit script cleanly on Ctrl+D

        # 4. Process valid selection
        chosen_vuln_summary = vulnerabilities[selected_index]
        vuln_id = chosen_vuln_summary.get('id')
        vuln_name = chosen_vuln_summary.get('attributes', {}).get('name', f"Vuln Index {selected_index+1}")

        if not vuln_id:
            print(f"[!] Could not determine the ID for the selected vulnerability ({vuln_name}). Please try another.")
            continue # Ask again

        # 5. Fetch detailed info for the chosen vulnerability
        vuln_details = get_vulnerability_details(api_key, vuln_id)

        # 6. Display detailed info
        if vuln_details:
            display_vulnerability_details(vuln_details)
        else:
            # Error message already printed by get_vulnerability_details
            print(f"[!] Could not display details for {vuln_id}. You can try another selection.")
            # Loop continues, user can try another or end

    print("\n[*] Script finished.")


if __name__ == "__main__":
    main()
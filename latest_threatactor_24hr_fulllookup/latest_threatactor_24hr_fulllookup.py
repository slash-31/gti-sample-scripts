#!/usr/bin/env python3
"""
Google Threat Intelligence Interactive Threat Actor Explorer (Looping & Saving)

This script:
1. Asks for a Google Threat Intelligence API key (requires Enterprise/Enterprise+).
2. Fetches the top 5 Google TI Threat Actors sorted by most recently modified first within the last 24 hours, and gets the TOTAL count modified in that period.
3. Presents the list of top 5 actors and the total count to the user.
4. Allows the user to select ONE actor (by number 1-5) from the initial list to explore.
5. Fetches specific relationships (reports, campaigns, vulnerabilities) for the chosen actor, sorted by recency via API.
6. Fetches related IOCs (top 10 files, URLs, domains, IPs) for the chosen actor.
7. Displays the fetched relationships and IOCs (most recent first), indicating the sort date field and highlighting recent relationship items.
8. Prompts the user again to select another actor (1-5) from the initial list or type 'end' to quit.
9. Repeats steps 4-8 until the user quits.
10. Saves the initial actor list and all explored actor data to a JSON file upon exit.

Usage:
    python <script_name>.py

Requirements:
    - requests
    - tabulate (pip install tabulate)
    - A Google Threat Intelligence API key with Enterprise or Enterprise Plus privileges.
"""

import requests
import json
import sys
import os # Needed for creating output directory
from datetime import datetime, timedelta, timezone
# Ensure tabulate is imported early to catch missing dependency
try:
    from tabulate import tabulate
except ImportError:
    print("[!] ERROR: 'tabulate' library not found. Please install it: pip install tabulate", file=sys.stderr)
    sys.exit(1)
import time
import random
import getpass  # For secure API key input
from requests.exceptions import RequestException
import urllib.parse # To encode filters

# --- Configuration ---
API_BASE_URL = "https://www.virustotal.com/api/v3" # Endpoint hosts Google TI data
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 5
IOC_LIMIT_PER_TYPE = 10 # Limit IOCs displayed per type - SET TO 10
RELATIONSHIP_LIMIT = 15 # Limit relationships displayed per type
ACTOR_FETCH_LIMIT = 5 # Fetch top 5 actors for display
OUTPUT_DIR = "output" # Directory to save JSON results
RECENT_THRESHOLD_SECONDS = 24 * 60 * 60 # Threshold for highlighting recent items (e.g., 1 day)

# --- API Request Function ---
def make_api_request(url, api_key, params=None, max_retries=MAX_RETRIES, retry_delay=RETRY_DELAY):
    """Makes API request with retry logic. Returns JSON or None."""
    headers = {"accept": "application/json", "x-apikey": api_key}
    attempt = 0
    last_exception = None
    query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote) if params else ""
    full_url = f"{url}?{query_string}" if query_string else url

    while attempt < max_retries:
        # print(f"  [*] Attempt {attempt+1}: Requesting {url} with params {params}", file=sys.stderr) # Debug
        try:
            response = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            # print(f"  [*] Response Status Code: {response.status_code}", file=sys.stderr) # Debug

            if response.status_code == 429:
                 wait_time = int(response.headers.get('Retry-After', retry_delay * (2 ** attempt)))
                 print(f"  [!] Rate limited ({response.status_code}). Retrying in {wait_time} seconds...", file=sys.stderr)
                 time.sleep(wait_time + random.uniform(0, 1))
                 attempt += 1
                 continue
            elif response.status_code == 401:
                 print(f"  [!] ERROR: API Key invalid or expired ({response.status_code}).", file=sys.stderr)
                 return None
            elif response.status_code == 403:
                 print(f"  [!] ERROR: Insufficient privileges ({response.status_code}).", file=sys.stderr)
                 print(f"      Check if API key has Google TI Enterprise/Enterprise+ license.", file=sys.stderr)
                 return None
            # Treat 400 Bad Request as potentially fatal for this request (e.g., bad sort param)
            elif response.status_code == 400:
                 print(f"  [!] ERROR: Bad Request ({response.status_code}) for URL {full_url}.", file=sys.stderr)
                 print(f"      Response: {response.text}", file=sys.stderr)
                 return None # Don't retry bad requests
            elif response.status_code >= 500:
                 print(f"  [!] Server error ({response.status_code}). Retrying...", file=sys.stderr)
                 time.sleep(retry_delay * (2 ** attempt) + random.uniform(0, 1))
                 attempt += 1
                 continue

            response.raise_for_status() # Raise HTTPError for other 4xx errors
            return response.json()

        except RequestException as e:
            last_exception = e
            # print(f"  [!] Request attempt {attempt + 1} failed: {e}. Retrying...", file=sys.stderr) # Debug
            time.sleep(retry_delay * (2 ** attempt) + random.uniform(0, 1))
            attempt += 1

    print(f"  [!] ERROR: API request failed after {max_retries} attempts. URL: {full_url}. Last error: {last_exception}", file=sys.stderr)
    return None

# --- Function to fetch top threat actors ---
def get_top_threat_actors(api_key, limit=ACTOR_FETCH_LIMIT):
    """
    Fetches the most recently updated threat actors from Google TI using the /collections endpoint.
    Returns a tuple: (list_of_top_actors, total_count)
    """
    print(f"[*] Fetching top {limit} Google TI Threat Actors modified in the last 24 hours...")
    filters = "collection_type:threat-actor last_modification_date:1d+"
    order = "last_modification_date-" # Descending sort for most recent first
    params = {'filter': filters, 'order': order, 'limit': limit}
    url = f"{API_BASE_URL}/collections"

    response_data = make_api_request(url, api_key, params=params)

    actors_list = []
    total_count = None

    if response_data and 'data' in response_data:
        actors_list = response_data['data']
        print(f"[*] Found {len(actors_list)} actor(s) for display.")
        # Attempt to get total count from meta information
        total_count = response_data.get('meta', {}).get('count')
        # We don't display total count here anymore, but return it

    else:
        print(f"  [!] Failed to fetch Threat Actors from {url} with params {params}.", file=sys.stderr)

    return actors_list, total_count # Return both list and count

# --- Function to display actor choices ---
def display_actor_choices(actors):
    """Displays a numbered list of actors for user selection."""
    if not actors: return False
    current_time_utc = datetime.now(timezone.utc)
    # Adjusted title slightly for clarity when repeated
    print(f"\n--- Top {len(actors)} Google TI Threat Actors (Updated Last 24 Hours as of {current_time_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}) ---")
    table_data = []
    headers = ["#", "Name", "Last Modified (UTC)", "ID"]
    for i, actor in enumerate(actors):
        attributes = actor.get('attributes', {})
        name = attributes.get('name', 'Unknown Name')
        actor_id = actor.get('id', 'N/A') # The collection ID representing the actor
        last_mod_ts = attributes.get('last_modification_date')
        last_mod_str = 'N/A'
        if isinstance(last_mod_ts, (int, float)) and last_mod_ts > 0:
             try:
                 last_mod_str = datetime.fromtimestamp(last_mod_ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
             except (TypeError, ValueError, OSError):
                 last_mod_str = 'Invalid Date'
        table_data.append([i + 1, name, last_mod_str, actor_id])
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    return True

# --- Function to fetch related IOCs (Re-added) ---
def fetch_related_iocs(api_key, actor_collection_id, relationships=['files', 'urls', 'domains', 'ip_addresses'], limit_per_type=IOC_LIMIT_PER_TYPE):
    """Fetches various related IOCs for a given actor collection ID from Google TI."""
    all_iocs = {}
    print(f"\n[*] Fetching related IOCs from Google TI for Actor Collection ID: {actor_collection_id} (limit {limit_per_type} per type):")
    for rel in relationships:
        print(f"  - Fetching {rel}...")
        url = f"{API_BASE_URL}/collections/{actor_collection_id}/{rel}"
        # REMOVED 'order' parameter to prevent potential API errors. Sorting is handled client-side.
        params = {'limit': limit_per_type}
        response_data = make_api_request(url, api_key, params=params)
        if response_data and 'data' in response_data:
             all_iocs[rel] = response_data['data']
             print(f"    Found {len(all_iocs[rel])} {rel}.")
        else:
             all_iocs[rel] = []
             # Be explicit if fetch failed vs just no items found
             status_msg = "none found" if response_data is not None else "fetch failed" # Check if response_data itself is None
             print(f"    Failed to fetch {rel} or {status_msg}.")
    return all_iocs

# --- Function to display IOCs (Re-added with client-side sorting) ---
def display_fetched_iocs(iocs_data):
    """Displays fetched IOCs in tables, sorted client-side by newest first."""
    if not iocs_data: print("[!] No IOC data to display."); return
    print("\n--- Related IOCs (Sorted by Most Recent Activity/Submission First) ---")
    for ioc_type, iocs in iocs_data.items():
        if not iocs:
            print(f"\n--- No items found for {ioc_type.upper()} ---")
            continue # Skip if no IOCs for this type

        # Define sort key function for client-side sorting
        def get_sort_key(ioc):
            attributes = ioc.get('attributes', {})
            # Prioritize most recent timestamps: last_mod -> last_analysis -> first_sub -> creation
            ts = attributes.get('last_modification_date',
                 attributes.get('last_analysis_date',
                 attributes.get('first_submission_date',
                 attributes.get('creation_date', None))))
            # Return timestamp if it's a valid number, otherwise 0 for sorting
            return ts if isinstance(ts, (int, float)) else 0

        # Perform client-side sorting
        try:
            sorted_iocs = sorted(iocs, key=get_sort_key, reverse=True)
        except Exception as sort_err:
             print(f"  [!] Warning: Could not client-sort {ioc_type}: {sort_err}. Displaying fetched order.", file=sys.stderr)
             sorted_iocs = iocs # Fallback to original order if sort fails

        if not sorted_iocs:
            # This case should be rare if initial 'iocs' list was not empty, but good practice
            print(f"\n--- No displayable IOCs found for {ioc_type.upper()} after sorting ---")
            continue

        # Display only the top N results based on IOC_LIMIT_PER_TYPE
        display_limit = IOC_LIMIT_PER_TYPE
        print(f"\n--- Top {min(len(sorted_iocs), display_limit)} Related {ioc_type.upper()} ---")
        table_data = []
        headers = []

        for i, ioc in enumerate(sorted_iocs[:display_limit], 1): # Slice list for display limit
            attributes = ioc.get('attributes', {})
            # Use the sort key to get the relevant date for display
            date_ts = get_sort_key(ioc)
            date_str = 'N/A'
            if date_ts > 0:
                try:
                    date_str = datetime.fromtimestamp(date_ts, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                except (TypeError, ValueError, OSError):
                    date_str = 'Invalid Date'

            try:
                # Formatting logic...
                if ioc_type == "files":
                    if not headers: headers = ["#", "SHA-256", "Type", "Size(MB)", "Recency Date"]
                    size_val = attributes.get('size')
                    size_mb = round(size_val / (1024*1024), 2) if isinstance(size_val, (int, float)) and size_val > 0 else '?'
                    table_data.append([i, ioc.get('id', 'N/A'), attributes.get('type_description', '?'), size_mb, date_str])
                elif ioc_type == "urls":
                    if not headers: headers = ["#", "URL (Snippet)", "Last Analysis (M+S/T)", "Recency Date"]
                    url_full = attributes.get('url', 'N/A')
                    url_display = url_full[:70] + '...' if len(url_full) > 70 else url_full
                    stats = attributes.get('last_analysis_stats', {})
                    total_engines = sum(v for v in stats.values() if isinstance(v, (int, float)))
                    mal_sus = (stats.get('malicious', 0) if isinstance(stats.get('malicious'), (int, float)) else 0) + \
                              (stats.get('suspicious', 0) if isinstance(stats.get('suspicious'), (int, float)) else 0)
                    ratio = f"{mal_sus}/{total_engines}" if total_engines > 0 else "N/A"
                    table_data.append([i, url_display, ratio, date_str])
                elif ioc_type == "domains":
                    if not headers: headers = ["#", "Domain", "Last Analysis (M+S/T)", "Recency Date"]
                    stats = attributes.get('last_analysis_stats', {})
                    total_engines = sum(v for v in stats.values() if isinstance(v, (int, float)))
                    mal_sus = (stats.get('malicious', 0) if isinstance(stats.get('malicious'), (int, float)) else 0) + \
                              (stats.get('suspicious', 0) if isinstance(stats.get('suspicious'), (int, float)) else 0)
                    ratio = f"{mal_sus}/{total_engines}" if total_engines > 0 else "N/A"
                    table_data.append([i, ioc.get('id', 'N/A'), ratio, date_str])
                elif ioc_type == "ip_addresses":
                    if not headers: headers = ["#", "IP Address", "Country", "ASN Owner", "Last Analysis (M+S/T)", "Recency Date"]
                    stats = attributes.get('last_analysis_stats', {})
                    total_engines = sum(v for v in stats.values() if isinstance(v, (int, float)))
                    mal_sus = (stats.get('malicious', 0) if isinstance(stats.get('malicious'), (int, float)) else 0) + \
                              (stats.get('suspicious', 0) if isinstance(stats.get('suspicious'), (int, float)) else 0)
                    ratio = f"{mal_sus}/{total_engines}" if total_engines > 0 else "N/A"
                    table_data.append([i, ioc.get('id', 'N/A'), attributes.get('country', '??'), attributes.get('as_owner', '?'), ratio, date_str])
                else:
                     if not headers: headers = ["#", "ID", "Type", "Recency Date"]
                     table_data.append([i, ioc.get('id', 'N/A'), ioc.get('type', 'N/A'), date_str])
            except Exception as format_err:
                 print(f"  [!] Error formatting IOC {ioc.get('id', 'N/A')} of type {ioc_type}: {format_err}", file=sys.stderr)


        if table_data:
             try:
                 print(tabulate(table_data, headers=headers, tablefmt="pretty", stralign="left"))
             except Exception as tab_err:
                 print(f"  [!] Error generating table for {ioc_type}: {tab_err}", file=sys.stderr)
                 print("  Raw Data:", table_data)

# --- Function to fetch and display specific relationships (SORTED BY API) ---
def fetch_and_display_relationships(api_key, collection_id):
    """
    Fetches and displays specific relationships for a given collection ID,
    sorted by API, and highlights items updated/created in the last 24 hours.
    """
    # Updated list of relationships to fetch - ONLY reports, campaigns, vulnerabilities
    relationships_to_fetch = ['reports', 'campaigns', 'vulnerabilities']
    print(f"\n--- Fetching Relationships for Collection ID: {collection_id} (Sorted by API, Newest First) ---")
    all_relationships_data = {} # Store fetched data for saving later
    highlight_found = False # Flag to track if we add a note about highlighting
    now_ts = datetime.now(timezone.utc).timestamp() # Get current time once for comparison

    for rel_name in relationships_to_fetch:
        print(f"  - Fetching relationship: {rel_name}...")
        limit = RELATIONSHIP_LIMIT

        # Determine the sort order parameter based on relationship type
        order_param = None
        sort_field_for_display = None # Track which field API used for sorting
        date_column_header = "Relevant Date (UTC)" # Default header

        # Define sorting preferences
        if rel_name == 'reports':
            order_param = 'creation_date-'
            sort_field_for_display = 'creation_date'
            date_column_header = "Creation Date (UTC)"
        elif rel_name == 'campaigns':
            order_param = 'last_modification_date-'
            sort_field_for_display = 'last_modification_date'
            date_column_header = "Last Modified (UTC)"
        elif rel_name == 'vulnerabilities':
            # *** Use last_modification_date for sorting vulnerabilities ***
            order_param = 'last_modification_date-'
            sort_field_for_display = 'last_modification_date'
            date_column_header = "Last Modified (UTC)" # Reflecting the change

        url = f"{API_BASE_URL}/collections/{collection_id}/{rel_name}"
        params = {'limit': limit}
        if order_param:
            params['order'] = order_param # Add sorting parameter for API

        response_data = make_api_request(url, api_key, params=params)
        fetched_items = [] # Store items for this relationship

        if response_data and 'data' in response_data and response_data['data']:
            # API should have sorted the items if order_param was supported
            items = response_data['data']
            fetched_items = items # Store for saving
            print(f"    Found {len(items)} item(s) for '{rel_name}'.")

            table_data = []
            # Define headers - use dynamic date header + Highlight marker
            headers = ["#", "*", "ID", "Type", "Name/Title", date_column_header]

            for i, item in enumerate(items, 1):
                highlight_marker = "" # Marker for recent items
                item_id = item.get('id', 'N/A')
                # For vulnerabilities, display the CVE ID if available
                if rel_name == 'vulnerabilities':
                    item_id = item.get('attributes', {}).get('cve_id', item_id)

                item_type = item.get('type', 'N/A')
                attributes = item.get('attributes', {})
                # Try common name/title fields
                name_title = attributes.get('name', attributes.get('title', 'N/A'))

                # Extract the date field primarily used for sorting (or a fallback)
                date_ts = None
                if sort_field_for_display:
                    date_ts = attributes.get(sort_field_for_display)
                else: # Fallback if no specific sort field defined
                    date_ts = attributes.get('last_modification_date', attributes.get('creation_date', None))

                date_str = 'N/A'
                # Check if this item's date is within the threshold of NOW
                if isinstance(date_ts, (int, float)) and date_ts > 0:
                    try:
                        # Use consistent format
                        item_dt = datetime.fromtimestamp(date_ts, timezone.utc)
                        date_str = item_dt.strftime('%Y-%m-%d %H:%M:%S')

                        # Compare item's date to current time minus threshold
                        if date_ts >= (now_ts - RECENT_THRESHOLD_SECONDS):
                             highlight_marker = "*"
                             highlight_found = True # Set flag if any item is marked

                    except (TypeError, ValueError, OSError):
                        date_str = 'Invalid Date'

                table_data.append([i, highlight_marker, item_id, item_type, name_title, date_str])

            if table_data:
                # Display note about sorting if API sorting was attempted
                sort_note = f"(Sorted by API: {order_param})" if order_param else "(Order as received)"
                print(f"\n--- Top {len(table_data)} Related '{rel_name.upper()}' {sort_note} ---")
                try:
                    print(tabulate(table_data, headers=headers, tablefmt="pretty", stralign="left"))
                except Exception as tab_err:
                    print(f"  [!] Error generating table for {rel_name}: {tab_err}", file=sys.stderr)
            # else: # Reduce noise
            #      print(f"    No displayable items found for '{rel_name}'.")

        elif response_data and 'data' in response_data and not response_data['data']:
             # Explicitly state no items found
             print(f"    No items found for relationship '{rel_name}'.")
        else:
             # Error printed by make_api_request if fetch failed (e.g., 400 or retries exhausted)
             # We already printed failure message inside make_api_request if response_data is None
             # If response_data exists but has no 'data' key, it's an unexpected format
             if response_data is not None and 'data' not in response_data:
                  print(f"    Unexpected response format for relationship '{rel_name}'.")


        all_relationships_data[rel_name] = fetched_items # Store even if empty/failed for context

    # Add note about the highlight marker if any were found
    if highlight_found:
        # Updated note wording
        print(f"\n  (*) Note: Items marked with * were created/modified within the last {int(RECENT_THRESHOLD_SECONDS / 3600)} hours.")

    return all_relationships_data # Return fetched data

# --- Function to save results ---
def save_results_to_json(data_to_save, base_filename="gti_actor_exploration"):
    """Saves the collected session data to a timestamped JSON file."""
    # Check if there's actually exploration data to save
    if not data_to_save or not data_to_save.get("explored_actors_details"):
        print("\n[*] No exploration data collected during this session to save.")
        return

    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(OUTPUT_DIR, f"{base_filename}_{timestamp}.json")

        print(f"\n[*] Saving exploration results to {filename}...")
        with open(filename, 'w', encoding='utf-8') as f:
            # Use default=str to handle potential non-serializable objects like datetime
            json.dump(data_to_save, f, indent=4, ensure_ascii=False, default=str)
        print(f"[*] Successfully saved results.")

    except IOError as e:
        print(f"\n[!] ERROR: Could not write to file {filename}: {e}", file=sys.stderr)
    except TypeError as e:
         print(f"\n[!] ERROR: Could not serialize data to JSON: {e}. Check for non-standard data types.", file=sys.stderr)
    except Exception as e:
        print(f"\n[!] ERROR: An unexpected error occurred during saving: {e}", file=sys.stderr)


# --- Main Execution Logic ---
def main():
    """Main function to run the interactive Google TI Threat Actor explorer."""
    print("--- Google Threat Intelligence Interactive Threat Actor Explorer ---")
    print("--- Focus: Reports, Campaigns, Vulnerabilities & IOCs (Looping) ---") # Updated focus
    print("[!] IMPORTANT: Requires Google Threat Intelligence Enterprise/Enterprise+ License.")
    print("-" * 70)

    api_key = None
    try:
        api_key = os.environ.get("GTI_API_KEY")
        if api_key:
            print("[*] Using API Key found in GTI_API_KEY environment variable.")
        else:
            api_key = getpass.getpass("Please enter your Google Threat Intelligence (VirusTotal) API Key: ")
        if not api_key: print("[!] API Key cannot be empty. Exiting."); sys.exit(1)
    except EOFError: print("\n[!] Input cancelled. Exiting."); sys.exit(1)
    except Exception as e: print(f"\n[!] An error occurred reading the API key: {e}"); sys.exit(1)

    # Fetch actors and total count
    actors, total_actors_count = get_top_threat_actors(api_key) # Unpack tuple

    if actors is None: # Check if fetch failed entirely
        print("[!] Could not retrieve Google TI Threat Actor list. Check API key and permissions."); sys.exit(1)
    if not actors: # Check if list is empty
        print("[*] No Google TI Threat Actors found matching criteria (Modified last 24h)."); sys.exit(0)

    num_options = len(actors) # Number of options to choose from (1 to 5)

    # --- Display choices ONCE ---
    if not display_actor_choices(actors):
         print("[!] Failed to display actor choices. Exiting.")
         sys.exit(1)
    # Display total count if available
    if total_actors_count is not None:
        print(f"\n[*] Total unique threat actors modified in the last 24 hours: {total_actors_count}")
    else:
        print("\n[*] Total count of actors modified in the last 24 hours is unavailable.")


    # Initialize list to store results from the session
    explored_actors_data = []

    # --- RE-ADDED THE while True: LOOP ---
    while True:
        # --- DO NOT Display actor choices again inside the loop ---

        # Prompt refers to the initial list (1-5)
        prompt = f"\nEnter number (1-{num_options}) from the list above to explore details, or type 'end' to quit: "
        try:
            user_input = input(prompt).strip()
            if user_input.lower() == 'end':
                print("[*] 'end' command received. Exiting loop.") # Confirmation message
                break # Exit the main loop

            choice_int = int(user_input)
            if 1 <= choice_int <= num_options:
                selected_index = choice_int - 1
            else:
                print(f"[!] Invalid choice. Please enter a number between 1 and {num_options} or 'end'.")
                continue # Ask for input again

        except ValueError:
            print("[!] Invalid input. Please enter a number or 'end'.")
            continue # Ask for input again
        except EOFError:
             print("\n[!] Input cancelled.")
             break # Exit the main loop

        # --- Process the valid selection ---
        chosen_actor_collection = actors[selected_index] # Get from the initially fetched list
        actor_collection_id = chosen_actor_collection.get('id')
        actor_name = chosen_actor_collection.get('attributes', {}).get('name', f"Actor Index {selected_index+1}")

        if not actor_collection_id:
            print(f"[!] Could not determine the ID for selected actor collection ({actor_name}). Please try another.")
            continue # Ask for input again

        print(f"\n{'='*10} Exploring: {actor_name} (Collection ID: {actor_collection_id}) {'='*10}")

        # --- Fetch and display specified relationships (reports, campaigns, vulnerabilities) ---
        related_metadata = fetch_and_display_relationships(api_key, actor_collection_id)

        # --- Fetch and display IOCs ---
        relationships_to_fetch_iocs = ['files', 'urls', 'domains', 'ip_addresses']
        related_iocs = fetch_related_iocs(api_key, actor_collection_id, relationships=relationships_to_fetch_iocs)
        if not related_iocs or all(not v for v in related_iocs.values()):
            print(f"\n[*] No related IOCs found or fetched from Google TI for {actor_name}.")
        else:
            display_fetched_iocs(related_iocs) # Sorts and displays IOCs

        # --- Store results for this single exploration ---
        current_exploration = {
            "actor_collection_info": chosen_actor_collection,
            "fetched_relationships": related_metadata,
            "fetched_iocs": related_iocs # Add IOCs to saved data
        }
        explored_actors_data.append(current_exploration) # Add to list for saving

        print(f"\n{'='*10} Finished exploring: {actor_name} {'='*10}")
        print("-" * 70) # Add separator before prompting again


    # --- Loop has ended ---

    # Save the results accumulated during the session
    final_data_to_save = {
        "session_info": {
            "script_run_time_utc": datetime.now(timezone.utc).isoformat(),
            "initial_actors_presented": actors,
            "total_actors_last_24h" : total_actors_count # Save the total count too
        },
        "explored_actors_details": explored_actors_data # List containing all explorations
    }
    save_results_to_json(final_data_to_save)

    print("\n[*] Script finished.")


if __name__ == "__main__":
    # Check for dependencies before running main
    try:
        import requests
        from tabulate import tabulate # Import specifically needed
        import getpass
    except ImportError as e:
        print(f"[!] Missing required library: {e.name}. Please install it (e.g., pip install {e.name})", file=sys.stderr)
        sys.exit(1)

    main() # Call main which now contains the core logic


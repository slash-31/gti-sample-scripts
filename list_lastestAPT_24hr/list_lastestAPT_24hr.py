#!/usr/bin/env python3
import requests
import json
import getpass
import time
import urllib.parse
import random # Added for jitter
from datetime import datetime

def get_recent_threat_actors(api_key, max_retries=5, initial_delay=5): # Increased defaults
    """
    Fetches threat actors modified in the last 24 hours (1 day) from the
    VirusTotal API, handling pagination and retrying on transient errors
    with exponential backoff and jitter. Returns partial results if errors
    occur after fetching some pages.

    Args:
        api_key (str): Your VirusTotal API key.
        max_retries (int): Maximum number of retry attempts for transient errors.
        initial_delay (int): Initial delay in seconds before the first retry.

    Returns:
        list: A list of found threat actor objects. Returns partial list if
              a persistent error occurs during pagination after some results
              have been fetched. Returns None only if an error occurs before
              any results are fetched or on non-retryable API errors.
    """
    base_url = "https://www.virustotal.com/api/v3/collections"

    # Construct headers with the API key
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    # --- Filter and Order ---
    filter_string = 'last_modification_date:1d+ collection_type:threat-actor'
    order_string = 'last_modification_date-'

    all_actors = []
    cursor = None
    page_count = 0
    limit = 40 # Max results per page

    print(f"Fetching data from VirusTotal API (Filter: '{filter_string}')...")

    while True:
        page_count += 1
        print(f"Attempting to fetch page {page_count}...")

        # Construct query parameters for this page
        params = {
            'filter': filter_string, # Pass raw string to requests params
            'order': order_string,
            'limit': limit
        }
        if cursor:
            params['cursor'] = cursor

        # --- Retry Logic ---
        for attempt in range(max_retries):
            response = None # Ensure response is defined in this scope
            try:
                # Make the GET request
                response = requests.get(base_url, headers=headers, params=params)
                response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

                print(f"  Page {page_count} Status Code: {response.status_code} (Attempt {attempt + 1}/{max_retries})")

                # Parse the JSON response
                data = response.json()

                # Check if 'data' key exists and contains a list
                if 'data' in data and isinstance(data['data'], list):
                    found_actors = data['data']
                    all_actors.extend(found_actors)
                    print(f"  Found {len(found_actors)} actors on this page. Total collected: {len(all_actors)}")

                    # Check for the next cursor for pagination
                    cursor = data.get('meta', {}).get('cursor')
                    if not cursor:
                        print("  No more pages found.")
                        return all_actors # Successfully finished all pages
                    else:
                         print(f"  Next cursor found, preparing for next page...")
                         # Add a small delay between *successful* page fetches
                         time.sleep(1.5)
                         break # Exit retry loop, proceed to next page (outer while loop)

                elif 'error' in data:
                    # Handle non-transient API errors reported in JSON
                    print(f"API Error on page {page_count}: {data['error'].get('message', 'Unknown error')}")
                    print(f"Error Code: {data['error'].get('code', 'N/A')}")
                    print(f"Returning {len(all_actors)} actors collected before the error.")
                    # Return partial results if an error occurs mid-pagination
                    return all_actors if all_actors else None
                else:
                    # Handle unexpected response format
                    print(f"Unexpected response format on page {page_count}.")
                    print(f"Returning {len(all_actors)} actors collected before the error.")
                    return all_actors if all_actors else None

            except requests.exceptions.HTTPError as http_err:
                print(f"HTTP error occurred on page {page_count} (Attempt {attempt + 1}/{max_retries}): {http_err}")
                # Check if the error is retryable (5xx errors, 429 Too Many Requests)
                if response is not None and response.status_code in [429, 500, 502, 503, 504]:
                    if attempt < max_retries - 1:
                        # Calculate wait time with exponential backoff + jitter
                        wait_time = initial_delay * (2 ** attempt) + random.uniform(0, 1) # Add jitter
                        print(f"  Retryable error ({response.status_code}). Retrying in {wait_time:.2f} seconds...")
                        time.sleep(wait_time)
                        # Continue to the next attempt in the retry loop
                    else:
                        print(f"  Max retries ({max_retries}) reached for page {page_count} after retryable error.")
                        print(f"Last Response Body: {response.text if response else 'No response object'}")
                        print(f"Returning {len(all_actors)} actors collected before the error.")
                        return all_actors # Return partial results after exhausted retries
                else:
                    # Not a retryable error or no response object, print details and return partials
                    print(f"  Non-retryable HTTP error occurred.")
                    print(f"Last Response Body: {response.text if response else 'No response object'}")
                    if response is not None:
                         if response.status_code == 400:
                             print("Bad Request Error: Check the filter syntax and parameters.")
                         elif response.status_code == 401:
                            print("Authentication Error: Please check your API key and permissions.")
                         elif response.status_code == 403:
                             print("Permission Error: Your API key may not have the required privileges.")
                    print(f"Returning {len(all_actors)} actors collected before the error.")
                    return all_actors if all_actors else None # Return partials or None if nothing collected yet

            except requests.exceptions.RequestException as req_err:
                print(f"Request exception occurred on page {page_count} (Attempt {attempt + 1}/{max_retries}): {req_err}")
                if attempt < max_retries - 1:
                     wait_time = initial_delay * (2 ** attempt) + random.uniform(0, 1) # Add jitter
                     print(f"  Retrying in {wait_time:.2f} seconds...")
                     time.sleep(wait_time)
                     # Continue to the next attempt
                else:
                    print(f"  Max retries ({max_retries}) reached for page {page_count} due to RequestException.")
                    print(f"Returning {len(all_actors)} actors collected before the error.")
                    return all_actors # Return partial results

            except json.JSONDecodeError:
                print(f"Failed to decode JSON response from the API on page {page_count} (Attempt {attempt + 1}/{max_retries}).")
                print(f"Raw response: {response.text if response else 'No response object'}")
                # Treat JSON errors as potentially transient if status code was 200 but content bad
                if attempt < max_retries - 1:
                     wait_time = initial_delay * (2 ** attempt) + random.uniform(0, 1) # Add jitter
                     print(f"  Retrying in {wait_time:.2f} seconds...")
                     time.sleep(wait_time)
                     # Continue to the next attempt
                else:
                    print(f"  Max retries ({max_retries}) reached for page {page_count} due to JSONDecodeError.")
                    print(f"Returning {len(all_actors)} actors collected before the error.")
                    return all_actors # Return partial results

            except Exception as e:
                print(f"An unexpected error occurred on page {page_count} (Attempt {attempt + 1}/{max_retries}): {e}")
                # Stop immediately on other unexpected errors
                print(f"Returning {len(all_actors)} actors collected before the error.")
                return all_actors if all_actors else None

        # If the retry loop finishes without breaking (i.e., max retries exceeded for a retryable error),
        # the function would have returned 'all_actors' inside the loop.
        # We only get here if the 'break' after successful processing was hit.

    # This line should theoretically not be reached due to returns/breaks inside the loop
    return all_actors


if __name__ == "__main__":
    # Prompt the user securely for their API key
    try:
        vt_api_key = getpass.getpass("Please enter your VirusTotal API key: ")
    except Exception as e:
        print(f"Could not read API key: {e}")
        exit(1) # Exit if we can't get the key

    if not vt_api_key:
        print("API key cannot be empty.")
        exit(1)

    # Fetch the threat actors
    # Uses updated defaults: retries=5, delay=5
    actors = get_recent_threat_actors(vt_api_key)

    # Process and display the results
    if actors is not None: # Note: Now 'actors' could be a partial list even if None wasn't returned explicitly on error
        if actors:
            # Check if the function returned due to an error mid-way (by checking if the last page fetch might have failed)
            # This is heuristic - a more robust way would involve the function returning a status tuple (data, status_message)
            print(f"\nFetched {len(actors)} threat actor(s) modified in the last 24 hours (Note: List may be partial if errors occurred during pagination):")
            print("-" * 60)
            for i, actor in enumerate(actors):
                actor_id = actor.get('id', 'N/A')
                actor_name = actor.get('attributes', {}).get('name', 'Unknown Name')
                last_mod_timestamp = actor.get('attributes', {}).get('last_modification_date')

                # Convert timestamp to readable format if available
                last_mod_str = "N/A"
                if last_mod_timestamp:
                    try:
                        # Timestamps from VT are usually Unix timestamps (seconds since epoch)
                        last_mod_dt = datetime.utcfromtimestamp(last_mod_timestamp)
                        last_mod_str = last_mod_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                    except (ValueError, TypeError):
                        last_mod_str = f"Invalid timestamp ({last_mod_timestamp})"

                print(f"Actor #{i+1}:")
                print(f"  Name: {actor_name}")
                print(f"  ID: {actor_id}")
                print(f"  Last Modified: {last_mod_str}")
                print("-" * 60)
        else:
            # This case now means either truly no actors were found, OR an error occurred before the first page was fetched.
             print("\nNo threat actors found modified in the last 24 hours, or an error occurred before fetching any data.")
    else:
         # This case should now only happen if an error occurred very early, before any actors list was created/returned.
        print("\nScript finished due to an early error during data retrieval.")
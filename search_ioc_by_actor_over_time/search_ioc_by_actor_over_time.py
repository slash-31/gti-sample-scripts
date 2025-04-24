#!/usr/bin/env python3
"""
VirusTotal Threat Actor Finder

This script queries the VirusTotal API to retrieve a specific threat actor
that was modified within a specified time period. It then fetches all associated IOCs,
summarizes them by category, displays the top 10 from each category, and saves 
all data to a JSON file named after the threat actor.

Usage:
    python vt_threat_actor.py --api-key YOUR_API_KEY --actor-name "APT28" --time-period 24h

Requirements:
    - requests
    - tabulate
    - A valid VirusTotal API key
"""

import requests
import json
import time
import random
import sys
import os
import argparse
from datetime import datetime, timedelta
from tabulate import tabulate
from requests.exceptions import RequestException
from collections import defaultdict

def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: The parsed command-line arguments
    """
    parser = argparse.ArgumentParser(description='Query VirusTotal API for a specific threat actor and its IOCs')
    parser.add_argument('--api-key', required=True, help='VirusTotal API key')
    parser.add_argument('--actor-name', required=True, help='Name of the threat actor to search for')
    parser.add_argument('--time-period', default='24h', choices=['24h', '7d', '30d'], 
                        help='Time period for search (24h, 7d, 30d)')
    parser.add_argument('--max-retries', type=int, default=5, 
                       help='Maximum number of retries for API calls (default: 5)')
    parser.add_argument('--retry-delay', type=int, default=5,
                       help='Delay in seconds between retries (default: 5)')
    return parser.parse_args()

def make_api_request(url, params, headers, max_retries=5, retry_delay=5):
    """
    Make an API request with retry logic for handling temporary failures.
    
    Args:
        url (str): The API endpoint URL
        params (dict): Query parameters for the request
        headers (dict): Headers for the request
        max_retries (int): Maximum number of retry attempts
        retry_delay (int): Delay in seconds between retries
        
    Returns:
        dict: JSON response from the API
        
    Raises:
        RequestException: If the request fails after all retry attempts
    """
    attempt = 0
    last_exception = None
    
    while attempt < max_retries:
        try:
            response = requests.get(url, params=params, headers=headers)
            
            # If we get a 429 (Too Many Requests) or 5xx errors, retry
            if response.status_code in (429, 500, 502, 503, 504):
                # Get retry delay from response headers if available
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    try:
                        # Retry-After can be in seconds
                        wait_time = int(retry_after)
                    except ValueError:
                        # If conversion fails, use default
                        wait_time = retry_delay
                else:
                    # Use default delay with exponential backoff + jitter
                    wait_time = retry_delay * (2 ** attempt) + random.uniform(0, 1)
                
                print(f"Received {response.status_code} response. Retrying in {wait_time:.2f} seconds...")
                time.sleep(wait_time)
                attempt += 1
                continue
            
            # For other error status codes, raise the exception
            response.raise_for_status()
            
            # If we get here, the request was successful
            return response.json()
            
        except RequestException as e:
            print(f"Request attempt {attempt + 1} failed: {str(e)}")
            last_exception = e
            
            # Exponential backoff with jitter
            wait_time = retry_delay * (2 ** attempt) + random.uniform(0, 1)
            print(f"Retrying in {wait_time:.2f} seconds...")
            time.sleep(wait_time)
            attempt += 1
    
    # If we've exhausted all retries, raise the last exception
    if last_exception:
        raise last_exception
    else:
        raise RequestException("All retry attempts failed")

def get_recent_threat_actor(api_key, actor_name, time_period, max_retries=5, retry_delay=5):
    """
    Fetches a specific threat actor modified in the specified time period from the
    VirusTotal API, handling pagination and retrying on transient errors.

    Args:
        api_key (str): Your VirusTotal API key.
        actor_name (str): The name of the threat actor to search for.
        time_period (str): Time period for the search (e.g., '24h', '7d', '30d').
        max_retries (int): Maximum number of retry attempts for transient errors.
        retry_delay (int): Initial delay in seconds before the first retry.

    Returns:
        list: A list containing the found threat actor object or empty if not found.
              Returns None only if an error occurs.
    """
    base_url = "https://www.virustotal.com/api/v3/collections"

    # Construct headers with the API key
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    # Convert time_period to appropriate format for the filter
    if time_period == '24h':
        filter_time = '1d+'
    elif time_period == '7d':
        filter_time = '7d+'
    elif time_period == '30d':
        filter_time = '30d+'
    else:
        filter_time = '1d+'  # Default to 24 hours

    # --- Filter and Order ---
    filter_string = f'last_modification_date:{filter_time} collection_type:threat-actor name:{actor_name}'
    order_string = 'last_modification_date-'

    all_actors = []
    cursor = None
    page_count = 0
    limit = 40  # Max results per page

    print(f"Fetching data from VirusTotal API (Filter: '{filter_string}')...")

    try:
        while True:
            page_count += 1
            print(f"Attempting to fetch page {page_count}...")

            # Construct query parameters for this page
            params = {
                'filter': filter_string,
                'order': order_string,
                'limit': limit
            }
            if cursor:
                params['cursor'] = cursor

            # Make the API request with retry logic
            data = make_api_request(base_url, params, headers, max_retries, retry_delay)
            
            # Check if 'data' key exists and contains a list
            if 'data' in data and isinstance(data['data'], list):
                found_actors = data['data']
                all_actors.extend(found_actors)
                print(f"  Found {len(found_actors)} actors on this page. Total collected: {len(all_actors)}")

                # Check for the next cursor for pagination
                cursor = data.get('meta', {}).get('cursor')
                if not cursor:
                    print("  No more pages found.")
                    break  # Exit the loop when no more pages
                else:
                    print(f"  Next cursor found, preparing for next page...")
                    # Add a small delay between successful page fetches
                    time.sleep(1.5)
            else:
                # Handle unexpected response format
                print(f"Unexpected response format on page {page_count}.")
                if 'error' in data:
                    print(f"API Error: {data['error'].get('message', 'Unknown error')}")
                    print(f"Error Code: {data['error'].get('code', 'N/A')}")
                break

    except Exception as e:
        print(f"Error fetching threat actor data: {e}", file=sys.stderr)
        # Return partial results if we collected some data before the error
        print(f"Returning {len(all_actors)} actors collected before the error.")
        
    return all_actors

def get_timestamp_from_period(time_period):
    """
    Convert a time period string to a timestamp.
    
    Args:
        time_period (str): Time period string ('24h', '7d', '30d')
        
    Returns:
        int: Unix timestamp representing the time period ago
    """
    now = datetime.now()
    
    if time_period == '24h':
        filtered_time = now - timedelta(hours=24)
    elif time_period == '7d':
        filtered_time = now - timedelta(days=7)
    elif time_period == '30d':
        filtered_time = now - timedelta(days=30)
    else:
        filtered_time = now - timedelta(hours=24)  # Default to 24 hours
        
    return int(filtered_time.timestamp())

def fetch_all_iocs(api_key, threat_id, time_period, max_retries=5, retry_delay=5):
    """
    Fetch all IOCs (Files, IPs, URLs, Domains) associated with a threat actor,
    filtering by creation date based on the time period.
    
    Args:
        api_key (str): Your VirusTotal API key
        threat_id (str): The threat actor ID
        time_period (str): Time period for filtering by creation date ('24h', '7d', '30d')
        max_retries (int): Maximum number of retry attempts
        retry_delay (int): Delay in seconds between retries
        
    Returns:
        dict: Dictionary with IOCs by category
    """
    entity_types = ["file", "ip", "url", "domain"]
    base_url = f"https://www.virustotal.com/api/v3/collections/{threat_id}/search"
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    # Get the timestamp for filtering
    filter_timestamp = get_timestamp_from_period(time_period)
    
    # Dictionary to store IOCs by type
    all_iocs = {
        "files": [],
        "ips": [],
        "urls": [],
        "domains": []
    }
    
    # Map entity type to our dictionary keys
    type_map = {
        "file": "files",
        "ip": "ips", 
        "url": "urls",
        "domain": "domains"
    }
    
    print(f"\nFetching IOCs for threat actor ID: {threat_id}")
    print(f"Only showing IOCs with creation_date after: {datetime.fromtimestamp(filter_timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Fetch each type of IOC
    for entity_type in entity_types:
        print(f"\n--- Fetching {entity_type} IOCs ---")
        ioc_key = type_map[entity_type]
        
        cursor = None
        page_count = 0
        
        try:
            while True:
                page_count += 1
                print(f"Fetching {entity_type} page {page_count}...")
                
                # Construct query parameters for this page
                params = {
                    "query": f"entity:{entity_type}",
                    "limit": 40  # Maximum allowed by the API
                }
                
                if cursor:
                    params["cursor"] = cursor
                
                # Make the request with retry logic
                data = make_api_request(base_url, params, headers, max_retries, retry_delay)
                
                # Extract items from this page
                items = data.get('data', [])
                
                # Filter items by creation_date
                filtered_items = []
                for item in items:
                    attributes = item.get('attributes', {})
                    
                    # Get creation date based on entity type
                    creation_date = None
                    if entity_type == 'file' or entity_type == 'url':
                        creation_date = attributes.get('first_submission_date')
                    else:  # domain or IP
                        creation_date = attributes.get('creation_date')
                    
                    # If no creation date is available, use last_analysis_date as fallback
                    if creation_date is None:
                        creation_date = attributes.get('last_analysis_date')
                    
                    # Include item if it meets the filter criteria or if we can't determine
                    if creation_date is None or creation_date >= filter_timestamp:
                        filtered_items.append(item)
                
                all_iocs[ioc_key].extend(filtered_items)
                print(f"Found {len(filtered_items)} recent {entity_type} IOCs out of {len(items)} total. Total {entity_type}: {len(all_iocs[ioc_key])}")
                
                # Check if there's a next page
                meta = data.get('meta', {})
                cursor = meta.get('cursor')
                
                # If no cursor, we've reached the end
                if not cursor:
                    print(f"No more {entity_type} pages to fetch.")
                    break
                    
                # Add small delay between requests
                time.sleep(1.5)
                
        except Exception as e:
            print(f"Error fetching {entity_type} IOCs: {e}")
            print(f"Moving on to next entity type...")
            
    return all_iocs

def display_threat_actor_table(actors):
    """
    Display threat actor information in a formatted table
    
    Args:
        actors (list): List of threat actor objects
    """
    if not actors:
        print("No threat actors found.")
        return

    table_data = []
    headers = ["Name", "ID", "Last Modified", "Aliases", "Description", "Country"]

    for actor in actors:
        attributes = actor.get('attributes', {})
        name = attributes.get('name', 'Unknown Name')
        actor_id = actor.get('id', 'N/A')
        
        # Handle timestamp
        last_mod_timestamp = attributes.get('last_modification_date')
        last_mod_str = "N/A"
        if last_mod_timestamp:
            try:
                last_mod_dt = datetime.utcfromtimestamp(last_mod_timestamp)
                last_mod_str = last_mod_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            except (ValueError, TypeError):
                last_mod_str = f"Invalid timestamp ({last_mod_timestamp})"
        
        # Get aliases if available
        aliases = attributes.get('aliases', [])
        aliases_str = ", ".join(aliases) if aliases else "None"
        
        # Get description (truncated if needed)
        description = attributes.get('description', 'No description available')
        if description and len(description) > 50:
            description = description[:47] + "..."
        
        # Get country if available
        country = attributes.get('country', 'Unknown')
        
        table_data.append([name, actor_id, last_mod_str, aliases_str, description, country])
    
    print("\n=== Threat Actor Information ===")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def summarize_iocs(all_iocs):
    """
    Summarize the IOCs and display in a table
    
    Args:
        all_iocs (dict): Dictionary with IOCs by category
    
    Returns:
        dict: Summary of IOC counts
    """
    # Count the IOCs by type
    summary = {
        "files": len(all_iocs["files"]),
        "ips": len(all_iocs["ips"]),
        "urls": len(all_iocs["urls"]),
        "domains": len(all_iocs["domains"])
    }
    
    # Create a summary table
    table_data = []
    for ioc_type, count in summary.items():
        table_data.append([ioc_type.upper(), count])
    
    print("\n=== IOC Summary ===")
    print(tabulate(table_data, headers=["IOC Type", "Count"], tablefmt="grid"))
    
    return summary

def display_top_iocs(all_iocs, limit=10):
    """
    Display the top IOCs from each category
    
    Args:
        all_iocs (dict): Dictionary with IOCs by category
        limit (int): Number of top IOCs to display
    """
    for ioc_type, iocs in all_iocs.items():
        if not iocs:
            print(f"\nNo {ioc_type} found.")
            continue
            
        # Determine which fields to display for each IOC type
        if ioc_type == "files":
            headers = ["#", "SHA-256", "Type", "Size", "First Seen"]
            table_data = []
            
            for i, ioc in enumerate(iocs[:limit], 1):
                attributes = ioc.get('attributes', {})
                sha256 = ioc.get('id', 'N/A')
                file_type = attributes.get('type_description', 'Unknown')
                size = attributes.get('size', 'N/A')
                
                # Handle timestamp
                first_seen = attributes.get('first_submission_date')
                first_seen_str = "N/A"
                if first_seen:
                    try:
                        dt = datetime.utcfromtimestamp(first_seen)
                        first_seen_str = dt.strftime('%Y-%m-%d')
                    except (ValueError, TypeError):
                        first_seen_str = "Invalid timestamp"
                
                table_data.append([i, sha256, file_type, size, first_seen_str])
        
        elif ioc_type == "ips":
            headers = ["#", "IP Address", "Country", "ASN Owner", "Last Analysis"]
            table_data = []
            
            for i, ioc in enumerate(iocs[:limit], 1):
                attributes = ioc.get('attributes', {})
                ip = ioc.get('id', 'N/A')
                country = attributes.get('country', 'Unknown')
                asn_owner = attributes.get('as_owner', 'Unknown')
                
                # Get detection stats
                last_analysis = attributes.get('last_analysis_stats', {})
                malicious = last_analysis.get('malicious', 0)
                suspicious = last_analysis.get('suspicious', 0)
                total = sum(last_analysis.values()) if last_analysis else 0
                
                detection_ratio = f"{malicious + suspicious}/{total}" if total else "N/A"
                
                table_data.append([i, ip, country, asn_owner, detection_ratio])
        
        elif ioc_type == "urls":
            headers = ["#", "URL", "Last Analysis", "First Submission"]
            table_data = []
            
            for i, ioc in enumerate(iocs[:limit], 1):
                attributes = ioc.get('attributes', {})
                url = ioc.get('id', 'N/A')
                # Truncate long URLs
                if len(url) > 50:
                    url = url[:47] + "..."
                
                # Get detection stats
                last_analysis = attributes.get('last_analysis_stats', {})
                malicious = last_analysis.get('malicious', 0)
                suspicious = last_analysis.get('suspicious', 0)
                total = sum(last_analysis.values()) if last_analysis else 0
                
                detection_ratio = f"{malicious + suspicious}/{total}" if total else "N/A"
                
                # Handle timestamp
                first_seen = attributes.get('first_submission_date')
                first_seen_str = "N/A"
                if first_seen:
                    try:
                        dt = datetime.utcfromtimestamp(first_seen)
                        first_seen_str = dt.strftime('%Y-%m-%d')
                    except (ValueError, TypeError):
                        first_seen_str = "Invalid timestamp"
                
                table_data.append([i, url, detection_ratio, first_seen_str])
        
        elif ioc_type == "domains":
            headers = ["#", "Domain", "Creation Date", "Last Analysis"]
            table_data = []
            
            for i, ioc in enumerate(iocs[:limit], 1):
                attributes = ioc.get('attributes', {})
                domain = ioc.get('id', 'N/A')
                
                # Get creation date
                creation_date = attributes.get('creation_date')
                creation_date_str = "N/A"
                if creation_date:
                    try:
                        dt = datetime.utcfromtimestamp(creation_date)
                        creation_date_str = dt.strftime('%Y-%m-%d')
                    except (ValueError, TypeError):
                        creation_date_str = "Invalid timestamp"
                
                # Get detection stats
                last_analysis = attributes.get('last_analysis_stats', {})
                malicious = last_analysis.get('malicious', 0)
                suspicious = last_analysis.get('suspicious', 0)
                total = sum(last_analysis.values()) if last_analysis else 0
                
                detection_ratio = f"{malicious + suspicious}/{total}" if total else "N/A"
                
                table_data.append([i, domain, creation_date_str, detection_ratio])
        
        print(f"\n=== Top {min(limit, len(iocs))} {ioc_type.upper()} ===")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

def save_to_json_file(data, actor_name):
    """
    Save all data to a JSON file named after the actor
    
    Args:
        data (dict): Data to save
        actor_name (str): Name of the threat actor for the filename
        
    Returns:
        str: Path to the saved file, or None if save failed
    """
    if not data:
        print("No data to save.")
        return None
    
    try:
        # Create output directory if it doesn't exist
        os.makedirs('output', exist_ok=True)
        
        # Create filename based on actor name, replace spaces with underscores
        safe_name = actor_name.replace(" ", "_").lower()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"output/{safe_name}_threat_intel_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
            
        print(f"Successfully saved all data to {filename}")
        return filename
    except Exception as e:
        print(f"Error saving JSON file: {e}", file=sys.stderr)
        return None

def main():
    """
    Main function to execute the VirusTotal API query workflow.
    """
    args = parse_arguments()
    
    try:
        # Fetch the threat actor
        actors = get_recent_threat_actor(
            args.api_key, 
            args.actor_name, 
            args.time_period,
            args.max_retries,
            args.retry_delay
        )
        
        # Process and display the results
        if actors:
            print(f"\nFound {len(actors)} results for threat actor '{args.actor_name}':")
            
            # Display table with actor information
            display_threat_actor_table(actors)
            
            # Get the first actor's ID for IOC fetching
            actor_id = actors[0].get('id')
            if actor_id:
                # Fetch IOCs for this threat actor, filtering by creation date
                iocs = fetch_all_iocs(
                    args.api_key,
                    actor_id,
                    args.time_period,  # Pass time_period for filtering
                    args.max_retries,
                    args.retry_delay
                )
                
                # Create summary and display tables
                summary = summarize_iocs(iocs)
                display_top_iocs(iocs)
                
                # Prepare data for saving
                data = {
                    "actor": actors[0],
                    "iocs": iocs,
                    "summary": summary,
                    "filter_info": {
                        "time_period": args.time_period,
                        "filter_timestamp": get_timestamp_from_period(args.time_period),
                        "filter_date": datetime.fromtimestamp(get_timestamp_from_period(args.time_period)).strftime('%Y-%m-%d %H:%M:%S UTC')
                    }
                }
                
                # Save to JSON file
                filename = save_to_json_file(data, args.actor_name)
                if filename:
                    print(f"\nAll data has been saved to {filename}")
            else:
                print("Could not find a valid actor ID to fetch IOCs.")
                
        else:
            print(f"\nNo threat actor found with name '{args.actor_name}' modified in the specified time period.")
            
    except Exception as e:
        print(f"Unexpected error in main execution: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
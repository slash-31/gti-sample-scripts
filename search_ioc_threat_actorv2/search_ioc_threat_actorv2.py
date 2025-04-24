#!/usr/bin/env python3
"""
VirusTotal IOC Extractor

This script queries the VirusTotal API to retrieve all IOCs (Indicators of Compromise)
for a specific threat actor. It handles pagination to ensure all results are collected,
even when they exceed the API's per-request limit of 40 items. The script collects
all types of IOCs (Files, IPs, URLs, and Domains) and combines them into a single JSON file.

Usage:
    python vt_ioc_extractor.py --api-key YOUR_API_KEY

Requirements:
    - requests
    - A valid VirusTotal API key
"""

import argparse
import json
import requests
import sys
import os
import re
import time
from collections import defaultdict
from requests.exceptions import RequestException

def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: The parsed command-line arguments
    """
    parser = argparse.ArgumentParser(description='Query VirusTotal API for IOCs associated with a threat actor')
    parser.add_argument('--api-key', required=True, help='VirusTotal API key')
    parser.add_argument('--threat-id', default='09b06892-9738-5c53-b704-368d5ac8dd62',
                       help='Threat actor UUID (default: 09b06892-9738-5c53-b704-368d5ac8dd62)')
    parser.add_argument('--max-retries', type=int, default=5, 
                       help='Maximum number of retries for API calls (default: 5)')
    parser.add_argument('--retry-delay', type=int, default=5,
                       help='Delay in seconds between retries (default: 5)')
    return parser.parse_args()

def extract_threat_actor_name(threat_id):
    """
    Format the threat actor identifier for file naming.
    
    Args:
        threat_id (str): The threat actor UUID
        
    Returns:
        str: A formatted threat actor name for file naming
    """
    return f"threat-actor-{threat_id}"

def save_to_json(all_iocs, filename):
    """
    Save the collected IOC data to a JSON file.
    
    Args:
        all_iocs (dict): Dictionary of IOC types and their data
        filename (str): Base name for the output file
        
    Returns:
        bool: True if saving was successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs('output', exist_ok=True)

        # Save to file
        file_path = os.path.join('output', f"{filename}.json")
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(all_iocs, f, indent=2)

        print(f"Data saved to {file_path}")
        return True
    except Exception as e:
        print(f"Error saving data to file: {e}", file=sys.stderr)
        return False

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
            
            # If we get a 429 (Too Many Requests) or 503 (Service Unavailable), retry
            if response.status_code in (429, 503):
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
                    # Use default delay with exponential backoff
                    wait_time = retry_delay * (2 ** attempt)
                
                print(f"Received {response.status_code} response. Retrying in {wait_time} seconds...")
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
            
            # Exponential backoff
            wait_time = retry_delay * (2 ** attempt)
            print(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
            attempt += 1
    
    # If we've exhausted all retries, raise the last exception
    if last_exception:
        raise last_exception
    else:
        raise RequestException("All retry attempts failed")

def fetch_all_pages(base_url, query_params, headers, entity_type, max_retries, retry_delay):
    """
    Fetch all pages of results for a specific IOC type using cursor-based pagination.
    
    Args:
        base_url (str): The VirusTotal API base URL
        query_params (dict): Query parameters for the API request
        headers (dict): Headers for the API request
        entity_type (str): Type of entity being fetched (for logging)
        max_retries (int): Maximum number of retry attempts per request
        retry_delay (int): Delay in seconds between retries
        
    Returns:
        list: All IOCs of the specified type
        int: Number of pages fetched
    """
    all_items = []
    cursor = None
    page_count = 0

    # Update query params to include the specific entity type
    query_params = query_params.copy()  # Create a copy to avoid modifying the original
    query_params["query"] = f"entity:{entity_type}"
    
    # Loop until we've exhausted all results
    while True:
        page_count += 1
        print(f"Fetching {entity_type} page {page_count}...")
        
        # Add cursor to query params if we have one
        if cursor:
            query_params["cursor"] = cursor
        else:
            # Remove cursor if present from previous entity type
            query_params.pop("cursor", None)
        
        try:
            # Make the request with retry logic
            data = make_api_request(base_url, query_params, headers, max_retries, retry_delay)
            
            # Extract items from this page
            items = data.get('data', [])
            all_items.extend(items)
            print(f"Found {len(items)} {entity_type} IOCs on this page.")
            
            # Check if there's a next page
            meta = data.get('meta', {})
            cursor = meta.get('cursor')
            
            # If no cursor, we've reached the end
            if not cursor:
                print(f"No more {entity_type} pages to fetch.")
                break
                
        except Exception as e:
            print(f"Error fetching {entity_type} page {page_count}: {str(e)}")
            print(f"Moving on to next entity type...")
            break
            
    return all_items, page_count

def summarize_iocs(all_iocs):
    """
    Summarize the collected IOCs by type.
    
    Args:
        all_iocs (dict): Dictionary of IOC types and their data
        
    Returns:
        dict: Summary statistics of IOCs by type
    """
    summary = {}
    
    for ioc_type, iocs in all_iocs.items():
        summary[ioc_type] = len(iocs)
        
        # Print sample of each type
        if iocs:
            print(f"\nSample of {ioc_type} IOCs:")
            for i, ioc in enumerate(iocs[:5], 1):
                ioc_id = ioc.get('id', 'Unknown')
                print(f"{i}. {ioc_id}")
    
    # Print overall summary
    print("\nSummary:")
    for ioc_type, count in summary.items():
        print(f"{ioc_type}: {count}")
        
    return summary

def main():
    """
    Main function to execute the VirusTotal API query workflow.
    
    The function:
    1. Parses command-line arguments
    2. Sets up the VirusTotal API request
    3. Fetches all pages of results for each IOC type using cursor-based pagination
    4. Saves the collected data to a single JSON file
    5. Displays summary information about the collected IOCs
    """
    args = parse_arguments()
    
    # Entity types to fetch
    entity_types = ["file", "ip", "url", "domain"]
    
    threat_id = args.threat_id
    base_url = f"https://www.virustotal.com/api/v3/collections/threat-actor--{threat_id}/search"
    query_params = {
        "fs:1d+": "",
        "limit": 40  # Maximum allowed by the API
    }
    headers = {
        "accept": "application/json",
        "x-apikey": args.api_key
    }

    # Dictionary to store IOCs by type
    all_iocs = {
        "files": [],
        "ips": [],
        "urls": [],
        "domains": []
    }
    
    # Track total pages fetched
    total_pages = 0
    
    try:
        # Fetch each type of IOC
        for entity_type in entity_types:
            print(f"\n--- Fetching {entity_type} IOCs ---")
            
            # Map entity type to our dictionary keys
            ioc_key = {
                "file": "files",
                "ip": "ips", 
                "url": "urls",
                "domain": "domains"
            }[entity_type]
            
            # Fetch all pages for this entity type
            iocs, pages = fetch_all_pages(
                base_url, 
                query_params, 
                headers, 
                entity_type,
                args.max_retries,
                args.retry_delay
            )
            all_iocs[ioc_key] = iocs
            total_pages += pages
            
            # Save progress after each entity type in case of failure later
            threat_actor_name = extract_threat_actor_name(threat_id)
            save_to_json(all_iocs, f"{threat_actor_name}_progress")

        # Extract threat actor name
        threat_actor_name = extract_threat_actor_name(threat_id)

        # Save all gathered IOCs to JSON file
        save_to_json(all_iocs, threat_actor_name)

        # Summarize and display information about all IOCs
        summary = summarize_iocs(all_iocs)
        
        # Add summary to the all_iocs dictionary
        all_iocs["summary"] = summary
        
        # Save updated JSON with summary
        save_to_json(all_iocs, threat_actor_name)
        
        print(f"\nTotal pages fetched: {total_pages}")
        print(f"Total IOCs collected: {sum(summary.values())}")

    except Exception as e:
        print(f"Unexpected error in main execution: {e}", file=sys.stderr)
        
        # Try to save what we've collected so far
        try:
            threat_actor_name = extract_threat_actor_name(threat_id)
            save_to_json(all_iocs, f"{threat_actor_name}_incomplete")
            print("Saved partial results to output directory.")
        except:
            print("Failed to save partial results.")
            
        sys.exit(1)

if __name__ == "__main__":
    main()
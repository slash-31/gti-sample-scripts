#!/usr/bin/env python3
"""
IoC_Pull.py

This script retrieves the top IoCs (Indicators of Compromise) for a specified threat actor 
from Google Threat Intelligence and keeps a local JSON file updated.

Usage:
    python IoC_Pull.py --threat-actor-id <uuid> --api-key <key> [--limit <limit>]

Author: Claude
Date: April 23, 2025
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
import requests
import xml.etree.ElementTree as ET


# Configure logging with XML format
def setup_logging():
    """
    Set up logging in XML format.
    """
    class XMLFormatter(logging.Formatter):
        def format(self, record):
            # Create the XML structure
            log_entry = ET.Element("log_entry")
            ET.SubElement(log_entry, "timestamp").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ET.SubElement(log_entry, "level").text = record.levelname
            ET.SubElement(log_entry, "message").text = record.getMessage()
            
            # Convert to string
            return ET.tostring(log_entry, encoding='unicode')

    # Set up the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Create file handler for XML logs
    file_handler = logging.FileHandler('IoC_Logs.xml', 'a')
    file_handler.setFormatter(XMLFormatter())
    root_logger.addHandler(file_handler)
    
    # Create console handler for display
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root_logger.addHandler(console_handler)
    
    return root_logger

# Initialize logger
logger = setup_logging()


class IoC_Puller:
    """
    Class to handle pulling IoCs from Google Threat Intelligence.
    """
    
    def __init__(self, api_key, threat_actor_id, limit=20, max_retries=5, retry_delay=5):
        """
        Initialize the IoC Puller with API key and threat actor details.
        
        Args:
            api_key (str): Google Threat Intelligence API key
            threat_actor_id (str): UUID of the threat actor to retrieve IoCs for
            limit (int): Maximum number of IoCs to retrieve per type
            max_retries (int): Maximum number of retries for API calls
            retry_delay (int): Delay in seconds between retries
        """
        self.api_key = api_key
        self.threat_actor_id = threat_actor_id
        self.limit = limit
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        self.json_file = "IoC_active.json"
        # Entity types to fetch (file, IP, URL, and domain)
        self.entity_types = ["file", "ip", "url", "domain"]

    def make_api_request(self, url, params):
        """
        Make an API request with retry logic for handling temporary failures.
        
        Args:
            url (str): The API endpoint URL
            params (dict): Query parameters for the request
            
        Returns:
            dict: JSON response from the API
        """
        attempt = 0
        
        while attempt < self.max_retries:
            try:
                response = requests.get(url, params=params, headers=self.headers)
                
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
                            wait_time = self.retry_delay
                    else:
                        # Use default delay with exponential backoff
                        wait_time = self.retry_delay * (2 ** attempt)
                    
                    logger.warning(f"Received {response.status_code} response. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    attempt += 1
                    continue
                
                # For other error status codes, raise the exception
                response.raise_for_status()
                
                # If we get here, the request was successful
                return response.json()
                
            except Exception as e:
                logger.error(f"Request attempt {attempt + 1} failed: {str(e)}")
                
                # Exponential backoff
                wait_time = self.retry_delay * (2 ** attempt)
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                attempt += 1
                
                # If this is the last attempt, raise the exception
                if attempt >= self.max_retries:
                    logger.error(f"All {self.max_retries} retry attempts failed")
                    raise
        
        return None  # This should never be reached due to the raise above

    def get_threat_actor_iocs(self):
        """
        Retrieve IoCs associated with the specified threat actor.
        
        Returns:
            dict: Dictionary containing IoCs by type
        """
        # Collection URL for the threat actor
        collection_url = f"{self.base_url}/collections/threat-actor--{self.threat_actor_id}/search"
        
        all_iocs = {
            "files": [],
            "ips": [],
            "urls": [],
            "domains": []
        }
        
        # Fetch each type of IoC
        for entity_type in self.entity_types:
            logger.info(f"Fetching {entity_type} IoCs for threat actor ID: {self.threat_actor_id}")
            
            # Map entity type to our dictionary keys
            ioc_key = {
                "file": "files",
                "ip": "ips", 
                "url": "urls",
                "domain": "domains"
            }[entity_type]
            
            # Query parameters to get IoCs for the entity type
            # Using limit parameter to control the number of results
            params = {
                "query": f"entity:{entity_type}",
                "limit": self.limit
            }
            
            try:
                data = self.make_api_request(collection_url, params)
                
                if data and 'data' in data:
                    iocs = data['data']
                    
                    # Process and store the IOCs
                    processed_iocs = []
                    for item in iocs:
                        attributes = item.get('attributes', {})
                        
                        ioc = {
                            "id": item.get("id"),
                            "type": entity_type,
                            "name": attributes.get("names", ["Unknown"])[0] if attributes.get("names") else attributes.get("name", "Unknown"),
                            "created_date": attributes.get("first_submission_date"),
                            "modified_date": attributes.get("last_analysis_date"),
                            "threat_actor_id": self.threat_actor_id
                        }
                        processed_iocs.append(ioc)
                    
                    all_iocs[ioc_key] = processed_iocs
                    logger.info(f"Retrieved {len(processed_iocs)} {entity_type} IoCs")
                else:
                    logger.warning(f"No {entity_type} IoCs found or invalid response format")
            
            except Exception as e:
                logger.error(f"Error retrieving {entity_type} IoCs: {str(e)}")
        
        return all_iocs
    
    def load_existing_iocs(self):
        """
        Load existing IoCs from the JSON file.
        
        Returns:
            list: List of IoC dictionaries from the JSON file
        """
        if not os.path.exists(self.json_file):
            logger.info(f"JSON file {self.json_file} does not exist. Will create a new one.")
            return []
        
        try:
            with open(self.json_file, 'r') as f:
                iocs = json.load(f)
            logger.info(f"Loaded IoCs from {self.json_file}")
            return iocs
        except Exception as e:
            logger.error(f"Error loading IoCs from JSON file: {str(e)}")
            return []
    
    def save_iocs_to_json(self, iocs):
        """
        Save IoCs to the JSON file.
        
        Args:
            iocs (dict): Dictionary of IoC types and their data
        """
        try:
            with open(self.json_file, 'w') as f:
                json.dump(iocs, f, indent=2)
            logger.info(f"Saved IoCs to {self.json_file}")
        except Exception as e:
            logger.error(f"Error saving IoCs to JSON file: {str(e)}")
    
    def update_iocs(self):
        """
        Update the IoCs in the JSON file with the latest from the threat actor.
        
        This method will:
        1. Get IoCs for the threat actor
        2. Load existing IoCs from the JSON file
        3. Update the list of IoCs
        4. Save the updated IoCs to the JSON file
        
        Returns:
            bool: True if successful, False otherwise
        """
        # Get IoCs for the threat actor
        new_iocs = self.get_threat_actor_iocs()
        if not any(new_iocs.values()):
            logger.error(f"Failed to retrieve IoCs for threat actor ID: {self.threat_actor_id}")
            return False
        
        # Load existing IoCs from JSON file
        existing_data = self.load_existing_iocs()
        
        # Initialize existing_iocs if not present
        if not existing_data:
            existing_data = {
                "files": [],
                "ips": [],
                "urls": [],
                "domains": []
            }
        
        # Track changes for logging
        added_iocs = []
        updated_iocs = []
        removed_iocs = []
        
        # Process each IoC type
        for ioc_type in ["files", "ips", "urls", "domains"]:
            # Create dictionaries for easier lookup
            existing_iocs = {f"{ioc['type']}:{ioc['id']}": ioc for ioc in existing_data.get(ioc_type, [])}
            new_iocs_dict = {f"{ioc['type']}:{ioc['id']}": ioc for ioc in new_iocs.get(ioc_type, [])}
            
            # Track changes
            updated_type_iocs = []
            
            # Process new IoCs
            for ioc_key, ioc in new_iocs_dict.items():
                if ioc_key not in existing_iocs:
                    # New IoC, add to the list
                    updated_type_iocs.append(ioc)
                    added_iocs.append(ioc)
                    logger.info(f"New IoC discovered: {ioc['type']}:{ioc['id']} ({ioc['name']})")
                else:
                    # Existing IoC, check if it needs update
                    existing_ioc = existing_iocs[ioc_key]
                    if existing_ioc.get('modified_date') != ioc.get('modified_date'):
                        # IoC has been updated, replace with new info
                        updated_type_iocs.append(ioc)
                        updated_iocs.append(ioc)
                        logger.info(f"Updated IoC: {ioc['type']}:{ioc['id']} ({ioc['name']})")
                    else:
                        # No changes, keep the existing IoC
                        updated_type_iocs.append(existing_ioc)
            
            # Process existing IoCs not present in the new list
            for ioc_key, ioc in existing_iocs.items():
                if ioc_key not in new_iocs_dict:
                    # IoC no longer in the list for this threat actor
                    if ioc.get('threat_actor_id') == self.threat_actor_id:
                        removed_iocs.append(ioc)
                        logger.info(f"Removed IoC: {ioc['type']}:{ioc['id']} ({ioc['name']})")
                    else:
                        # IoC is for a different threat actor, keep it
                        updated_type_iocs.append(ioc)
            
            # Update the current type in the data structure
            existing_data[ioc_type] = updated_type_iocs
        
        # Update the JSON file
        self.save_iocs_to_json(existing_data)
        
        # Log all changes in XML format
        for ioc in added_iocs:
            logger.info(f"Added new IoC: {ioc['type']}:{ioc['id']} - {ioc['name']}")
            
        for ioc in updated_iocs:
            logger.info(f"Updated IoC: {ioc['type']}:{ioc['id']} - {ioc['name']}")
            
        for ioc in removed_iocs:
            logger.info(f"Removed IoC: {ioc['type']}:{ioc['id']} - {ioc['name']}")
        
        # Generate summary
        summary = {
            "files": len(existing_data.get("files", [])),
            "ips": len(existing_data.get("ips", [])),
            "urls": len(existing_data.get("urls", [])),
            "domains": len(existing_data.get("domains", [])),
            "total": sum(len(existing_data.get(t, [])) for t in ["files", "ips", "urls", "domains"])
        }
        
        logger.info(f"IoC Summary - Files: {summary['files']}, IPs: {summary['ips']}, URLs: {summary['urls']}, Domains: {summary['domains']}, Total: {summary['total']}")
        
        return True


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Google Threat Intelligence IoC Puller')
    parser.add_argument('--threat-actor-id', required=True, help='UUID of the threat actor')
    parser.add_argument('--api-key', required=True, help='Google Threat Intelligence API key')
    parser.add_argument('--limit', type=int, default=20, help='Maximum number of IoCs to retrieve per type (default: 20)')
    parser.add_argument('--max-retries', type=int, default=5, help='Maximum number of retry attempts for API calls (default: 5)')
    parser.add_argument('--retry-delay', type=int, default=5, help='Delay in seconds between retries (default: 5)')
    
    return parser.parse_args()


def main():
    """
    Main function to run the script.
    """
    args = parse_arguments()
    
    logger.info(f"Starting IoC_Pull for threat actor ID: {args.threat_actor_id}")
    
    puller = IoC_Puller(
        api_key=args.api_key,
        threat_actor_id=args.threat_actor_id,
        limit=args.limit,
        max_retries=args.max_retries,
        retry_delay=args.retry_delay
    )
    
    if puller.update_iocs():
        logger.info("IoC update completed successfully")
    else:
        logger.error("IoC update encountered errors. Check the log for details.")


if __name__ == "__main__":
    main()
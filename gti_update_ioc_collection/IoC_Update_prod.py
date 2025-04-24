#!/usr/bin/env python3
"""
IoC_Update.py

This script creates a Google Threat Intelligence IoC collection and adds IoCs from a local
JSON file. It also displays a table showing the IoC details and actions taken.

Usage:
    python IoC_Update.py --collection-name <name> --api-key <key>

Author: Claude
Date: April 24, 2025
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from prettytable import PrettyTable
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


class IoC_Updater:
    """
    Class to handle creating and updating IoCs in Google Threat Intelligence IoC collection.
    """
    
    def __init__(self, api_key, collection_name):
        """
        Initialize the IoC Updater with API key and collection details.
        
        Args:
            api_key (str): Google Threat Intelligence API key
            collection_name (str): Name of the IoC collection to manage
        """
        self.api_key = api_key
        self.collection_name = collection_name
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "x-apikey": self.api_key
        }
        self.json_file = "IoC_active.json"
        self.collection_id = None
        self.action_table = PrettyTable()
        self.action_table.field_names = ["IoC", "Name", "Created Date", "Modified Date", "Action"]
    
    def load_iocs_from_json(self):
        """
        Load IoCs from the JSON file.
        
        Returns:
            dict: Dictionary containing IoCs by type or None if file doesn't exist or error occurred
        """
        if not os.path.exists(self.json_file):
            logger.error(f"JSON file {self.json_file} does not exist")
            return None
        
        try:
            with open(self.json_file, 'r') as f:
                iocs = json.load(f)
            logger.info(f"Loaded IoCs from {self.json_file}")
            return iocs
        except Exception as e:
            logger.error(f"Error loading IoCs from JSON file: {str(e)}")
            return None
    
    def create_collection_with_iocs(self):
        """
        Create a new IoC collection with IoCs from the JSON file.
        
        Returns:
            bool: True if the collection was created successfully, False otherwise
        """
        # Load IoCs from JSON file
        iocs_data = self.load_iocs_from_json()
        if not iocs_data:
            logger.error("Failed to load IoCs from JSON file")
            return False
        
        # The correct endpoint for creating collections is '/collections'
        url = f"{self.base_url}/collections"
        
        # Log the request we're about to make
        logger.info(f"Creating IoC collection: {self.collection_name}")
        logger.info(f"Using URL: {url}")
        
        # Prepare the relationships for the request payload
        relationships = {}
        
        # Add files
        if "files" in iocs_data and iocs_data["files"]:
            files_data = []
            for ioc in iocs_data["files"]:
                files_data.append({
                    "type": "file",
                    "id": ioc["id"]
                })
                # Add to action table
                self.action_table.add_row([
                    ioc["id"], 
                    ioc.get("name", "Unknown"),
                    datetime.fromtimestamp(ioc.get("created_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("created_date") else "Unknown",
                    datetime.fromtimestamp(ioc.get("modified_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("modified_date") else "Unknown",
                    "add"
                ])
            if files_data:
                relationships["files"] = {"data": files_data}
        
        # Add domains
        if "domains" in iocs_data and iocs_data["domains"]:
            domains_data = []
            for ioc in iocs_data["domains"]:
                domains_data.append({
                    "type": "domain",
                    "id": ioc["id"]
                })
                # Add to action table
                self.action_table.add_row([
                    ioc["id"], 
                    ioc.get("name", "Unknown"),
                    datetime.fromtimestamp(ioc.get("created_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("created_date") else "Unknown",
                    datetime.fromtimestamp(ioc.get("modified_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("modified_date") else "Unknown",
                    "add"
                ])
            if domains_data:
                relationships["domains"] = {"data": domains_data}
        
        # Add URLs
        if "urls" in iocs_data and iocs_data["urls"]:
            urls_data = []
            for ioc in iocs_data["urls"]:
                urls_data.append({
                    "type": "url",
                    "id": ioc["id"]
                })
                # Add to action table
                self.action_table.add_row([
                    ioc["id"], 
                    ioc.get("name", "Unknown"),
                    datetime.fromtimestamp(ioc.get("created_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("created_date") else "Unknown",
                    datetime.fromtimestamp(ioc.get("modified_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("modified_date") else "Unknown",
                    "add"
                ])
            if urls_data:
                relationships["urls"] = {"data": urls_data}
        
        # Add IPs
        if "ips" in iocs_data and iocs_data["ips"]:
            ips_data = []
            for ioc in iocs_data["ips"]:
                ips_data.append({
                    "type": "ip_address",
                    "id": ioc["id"]
                })
                # Add to action table
                self.action_table.add_row([
                    ioc["id"], 
                    ioc.get("name", "Unknown"),
                    datetime.fromtimestamp(ioc.get("created_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("created_date") else "Unknown",
                    datetime.fromtimestamp(ioc.get("modified_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("modified_date") else "Unknown",
                    "add"
                ])
            if ips_data:
                relationships["ip_addresses"] = {"data": ips_data}
        
        # Prepare the request payload using the correct format
        data = {
            "data": {
                "type": "collection",
                "attributes": {
                    "name": self.collection_name,
                    "description": f"IoC collection for {self.collection_name} managed by IoC_Update"
                }
            }
        }
        
        # Add relationships if we have any
        if relationships:
            data["data"]["relationships"] = relationships
        
        try:
            # Make the request
            response = requests.post(url, headers=self.headers, json=data)
            
            # Log the response status code
            logger.info(f"Response status code: {response.status_code}")
            
            # Check if the response is successful
            if response.status_code == 200:
                logger.info(f"Created new IoC collection: {self.collection_name}")
                response_data = response.json()
                self.collection_id = response_data.get('data', {}).get('id')
                logger.info(f"Collection ID: {self.collection_id}")
                return True
            elif response.status_code == 400:
                # Collection might already exist
                response_json = response.json()
                error_msg = response_json.get("error", {}).get("message", "")
                logger.info(f"Response error message: {error_msg}")
                if "already exists" in error_msg:
                    logger.info(f"IoC collection {self.collection_name} already exists")
                    # If collection already exists, try to update it instead
                    return self.update_existing_collection()
                else:
                    logger.error(f"Error creating collection: {error_msg}")
                    return False
            else:
                # Log the detailed error response
                try:
                    error_details = response.json()
                    logger.error(f"Error creating collection: {response.status_code} - {error_details}")
                except:
                    logger.error(f"Error creating collection: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Exception while creating collection: {str(e)}")
            return False
    
    def update_existing_collection(self):
        """
        Update an existing collection with IoCs from the JSON file.
        
        Returns:
            bool: True if the collection was updated successfully, False otherwise
        """
        # First, we need to get the collection ID
        url = f"{self.base_url}/intelligence/search"
        params = {
            "query": f'name:"{self.collection_name}" type:collection',
            "limit": 1
        }
        
        try:
            # Search for the collection
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data') and len(data['data']) > 0:
                    self.collection_id = data['data'][0]['id']
                    logger.info(f"Found existing collection: {self.collection_id}")
                    
                    # Now, let's get the existing IoCs in the collection
                    return self.sync_collection_with_json()
                else:
                    logger.error(f"Could not find collection: {self.collection_name}")
                    return False
            else:
                logger.error(f"Error searching for collection: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception while updating collection: {str(e)}")
            return False
    
    def sync_collection_with_json(self):
        """
        Synchronize the collection with IoCs from the JSON file.
        
        Returns:
            bool: True if the collection was synchronized successfully, False otherwise
        """
        # Load IoCs from JSON file
        json_iocs = self.load_iocs_from_json()
        if not json_iocs:
            logger.error("Failed to load IoCs from JSON file")
            return False
        
        # Get IoCs from the collection
        url = f"{self.base_url}/collections/{self.collection_id}/items"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                collection_data = response.json()
                collection_iocs = collection_data.get('data', [])
                
                # Create dictionaries for easier lookup
                collection_ioc_dict = {f"{ioc['type']}:{ioc['id']}": ioc for ioc in collection_iocs}
                
                # Process each IoC type from JSON
                all_json_iocs = []
                
                # Add files
                if "files" in json_iocs and json_iocs["files"]:
                    for ioc in json_iocs["files"]:
                        all_json_iocs.append({
                            "type": "file",
                            "id": ioc["id"],
                            "name": ioc.get("name", "Unknown"),
                            "created_date": ioc.get("created_date", 0),
                            "modified_date": ioc.get("modified_date", 0)
                        })
                
                # Add domains
                if "domains" in json_iocs and json_iocs["domains"]:
                    for ioc in json_iocs["domains"]:
                        all_json_iocs.append({
                            "type": "domain",
                            "id": ioc["id"],
                            "name": ioc.get("name", "Unknown"),
                            "created_date": ioc.get("created_date", 0),
                            "modified_date": ioc.get("modified_date", 0)
                        })
                
                # Add URLs
                if "urls" in json_iocs and json_iocs["urls"]:
                    for ioc in json_iocs["urls"]:
                        all_json_iocs.append({
                            "type": "url",
                            "id": ioc["id"],
                            "name": ioc.get("name", "Unknown"),
                            "created_date": ioc.get("created_date", 0),
                            "modified_date": ioc.get("modified_date", 0)
                        })
                
                # Add IPs
                if "ips" in json_iocs and json_iocs["ips"]:
                    for ioc in json_iocs["ips"]:
                        all_json_iocs.append({
                            "type": "ip_address",
                            "id": ioc["id"],
                            "name": ioc.get("name", "Unknown"),
                            "created_date": ioc.get("created_date", 0),
                            "modified_date": ioc.get("modified_date", 0)
                        })
                
                # Create a dictionary of JSON IoCs for easier lookup
                json_ioc_dict = {f"{ioc['type']}:{ioc['id']}": ioc for ioc in all_json_iocs}
                
                # Find IoCs to add (in JSON but not in collection)
                iocs_to_add = []
                for ioc_key, ioc in json_ioc_dict.items():
                    if ioc_key not in collection_ioc_dict:
                        iocs_to_add.append(ioc)
                        # Add to action table
                        self.action_table.add_row([
                            ioc["id"], 
                            ioc.get("name", "Unknown"),
                            datetime.fromtimestamp(ioc.get("created_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("created_date") else "Unknown",
                            datetime.fromtimestamp(ioc.get("modified_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("modified_date") else "Unknown",
                            "add"
                        ])
                
                # Find IoCs to delete (in collection but not in JSON)
                iocs_to_delete = []
                for ioc_key, ioc in collection_ioc_dict.items():
                    if ioc_key not in json_ioc_dict:
                        iocs_to_delete.append(ioc)
                        # Add to action table
                        self.action_table.add_row([
                            ioc["id"], 
                            ioc.get("attributes", {}).get("name", "Unknown"),
                            "Unknown",  # We don't have this info from the collection
                            "Unknown",  # We don't have this info from the collection
                            "delete"
                        ])
                
                # Add new IoCs to the collection
                success = True
                for ioc in iocs_to_add:
                    if not self.add_ioc_to_collection(ioc):
                        success = False
                
                # Delete outdated IoCs from the collection
                for ioc in iocs_to_delete:
                    if not self.delete_ioc_from_collection(ioc):
                        success = False
                
                return success
            else:
                logger.error(f"Error getting collection IoCs: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception while syncing collection: {str(e)}")
            return False
    
    def add_ioc_to_collection(self, ioc):
        """
        Add an IoC to the collection.
        
        Args:
            ioc (dict): IoC information to add
            
        Returns:
            bool: True if successful, False otherwise
        """
        url = f"{self.base_url}/collections/{self.collection_id}/items"
        
        data = {
            "data": {
                "type": ioc["type"],
                "id": ioc["id"]
            }
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=data)
            
            if response.status_code == 200:
                logger.info(f"Added IoC {ioc['id']} to collection {self.collection_name}")
                return True
            else:
                logger.error(f"Error adding IoC to collection: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception while adding IoC to collection: {str(e)}")
            return False
    
    def delete_ioc_from_collection(self, ioc):
        """
        Delete an IoC from the collection.
        
        Args:
            ioc (dict): IoC information to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        url = f"{self.base_url}/collections/{self.collection_id}/items/{ioc['type']}/{ioc['id']}"
        
        try:
            response = requests.delete(url, headers=self.headers)
            
            if response.status_code == 200:
                logger.info(f"Deleted IoC {ioc['id']} from collection {self.collection_name}")
                return True
            else:
                logger.error(f"Error deleting IoC from collection: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception while deleting IoC from collection: {str(e)}")
            return False
    
    def display_action_table(self):
        """
        Display the action table.
        """
        if self.action_table.rowcount > 0:
            print("\nActions taken on IoCs:")
            print(self.action_table)
        else:
            print("\nNo actions taken on IoCs.")


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Google Threat Intelligence IoC Updater')
    parser.add_argument('--collection-name', required=True, help='Name of the IoC collection')
    parser.add_argument('--api-key', required=True, help='Google Threat Intelligence API key')
    
    return parser.parse_args()


def main():
    """
    Main function to run the script.
    """
    args = parse_arguments()
    
    logger.info(f"Starting IoC_Update for collection: {args.collection_name}")
    
    updater = IoC_Updater(
        api_key=args.api_key,
        collection_name=args.collection_name
    )
    
    if updater.create_collection_with_iocs():
        logger.info("IoC collection creation/update completed successfully")
        updater.display_action_table()
    else:
        logger.error("IoC collection creation/update encountered errors. Check the log for details.")


if __name__ == "__main__":
    main()
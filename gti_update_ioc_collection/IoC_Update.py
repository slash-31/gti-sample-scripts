#!/usr/bin/env python3
"""
IoC_Update.py

This script creates a Google Threat Intelligence IoC collection and adds IoCs from a local
JSON file. It also displays a table showing the IoC details and actions taken.

Usage:
    python IoC_Update.py --collection-name <name> --api-key <key> [--status-only]

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
    
    def __init__(self, api_key, collection_name, max_age=0):
        """
        Initialize the IoC Updater with API key and collection details.
        
        Args:
            api_key (str): Google Threat Intelligence API key
            collection_name (str): Name of the IoC collection to manage
            max_age (int): Maximum age of IoCs in days (0 means no removal)
        """
        self.api_key = api_key
        self.collection_name = collection_name
        self.max_age = max_age
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "x-apikey": self.api_key
        }
        self.json_file = "IoC_active.json"
        self.collection_id = None
        self.action_table = PrettyTable()
        self.action_table.field_names = ["IoC", "Name", "Last Modified", "Age (days)", "Action"]
    
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
                
                # Calculate the cutoff timestamp for age filtering
                current_time = datetime.now().timestamp()
                age_cutoff = 0
                if self.max_age > 0:
                    age_cutoff = current_time - (self.max_age * 24 * 60 * 60)  # Convert days to seconds
                
                # Processing counters
                total_iocs = 0
                iocs_to_keep = 0
                iocs_too_old = 0
                
                # Process Files
                if "files" in json_iocs and json_iocs["files"]:
                    kept_files = []
                    for ioc in json_iocs["files"]:
                        total_iocs += 1
                        modified_date = ioc.get("modified_date", 0)
                        
                        # Check if IoC is too old
                        if self.max_age > 0 and modified_date < age_cutoff:
                            iocs_too_old += 1
                            # Add to action table as "remove (age)"
                            age_days = int((current_time - modified_date) / (24 * 60 * 60))
                            self.action_table.add_row([
                                ioc["id"], 
                                ioc.get("name", "Unknown"),
                                datetime.fromtimestamp(modified_date).strftime("%Y-%m-%d %H:%M:%S") if modified_date else "Unknown",
                                age_days,
                                "remove (age)"
                            ])
                        else:
                            iocs_to_keep += 1
                            kept_files.append(ioc)
                            all_json_iocs.append({
                                "type": "file",
                                "id": ioc["id"],
                                "name": ioc.get("name", "Unknown"),
                                "created_date": ioc.get("created_date", 0),
                                "modified_date": modified_date
                            })
                    
                    # Update the JSON with filtered list
                    json_iocs["files"] = kept_files
                
                # Process Domains
                if "domains" in json_iocs and json_iocs["domains"]:
                    kept_domains = []
                    for ioc in json_iocs["domains"]:
                        total_iocs += 1
                        modified_date = ioc.get("modified_date", 0)
                        
                        # Check if IoC is too old
                        if self.max_age > 0 and modified_date < age_cutoff:
                            iocs_too_old += 1
                            # Add to action table as "remove (age)"
                            age_days = int((current_time - modified_date) / (24 * 60 * 60))
                            self.action_table.add_row([
                                ioc["id"], 
                                ioc.get("name", "Unknown"),
                                datetime.fromtimestamp(modified_date).strftime("%Y-%m-%d %H:%M:%S") if modified_date else "Unknown",
                                age_days,
                                "remove (age)"
                            ])
                        else:
                            iocs_to_keep += 1
                            kept_domains.append(ioc)
                            all_json_iocs.append({
                                "type": "domain",
                                "id": ioc["id"],
                                "name": ioc.get("name", "Unknown"),
                                "created_date": ioc.get("created_date", 0),
                                "modified_date": modified_date
                            })
                    
                    # Update the JSON with filtered list
                    json_iocs["domains"] = kept_domains
                
                # Process URLs
                if "urls" in json_iocs and json_iocs["urls"]:
                    kept_urls = []
                    for ioc in json_iocs["urls"]:
                        total_iocs += 1
                        modified_date = ioc.get("modified_date", 0)
                        
                        # Check if IoC is too old
                        if self.max_age > 0 and modified_date < age_cutoff:
                            iocs_too_old += 1
                            # Add to action table as "remove (age)"
                            age_days = int((current_time - modified_date) / (24 * 60 * 60))
                            self.action_table.add_row([
                                ioc["id"], 
                                ioc.get("name", "Unknown"),
                                datetime.fromtimestamp(modified_date).strftime("%Y-%m-%d %H:%M:%S") if modified_date else "Unknown",
                                age_days,
                                "remove (age)"
                            ])
                        else:
                            iocs_to_keep += 1
                            kept_urls.append(ioc)
                            all_json_iocs.append({
                                "type": "url",
                                "id": ioc["id"],
                                "name": ioc.get("name", "Unknown"),
                                "created_date": ioc.get("created_date", 0),
                                "modified_date": modified_date
                            })
                    
                    # Update the JSON with filtered list
                    json_iocs["urls"] = kept_urls
                
                # Process IPs
                if "ips" in json_iocs and json_iocs["ips"]:
                    kept_ips = []
                    for ioc in json_iocs["ips"]:
                        total_iocs += 1
                        modified_date = ioc.get("modified_date", 0)
                        
                        # Check if IoC is too old
                        if self.max_age > 0 and modified_date < age_cutoff:
                            iocs_too_old += 1
                            # Add to action table as "remove (age)"
                            age_days = int((current_time - modified_date) / (24 * 60 * 60))
                            self.action_table.add_row([
                                ioc["id"], 
                                ioc.get("name", "Unknown"),
                                datetime.fromtimestamp(modified_date).strftime("%Y-%m-%d %H:%M:%S") if modified_date else "Unknown",
                                age_days,
                                "remove (age)"
                            ])
                        else:
                            iocs_to_keep += 1
                            kept_ips.append(ioc)
                            all_json_iocs.append({
                                "type": "ip_address",
                                "id": ioc["id"],
                                "name": ioc.get("name", "Unknown"),
                                "created_date": ioc.get("created_date", 0),
                                "modified_date": modified_date
                            })
                    
                    # Update the JSON with filtered list
                    json_iocs["ips"] = kept_ips
                
                # Log the age filtering results
                if self.max_age > 0:
                    logger.info(f"Age filtering: {total_iocs} total IoCs, {iocs_to_keep} kept, {iocs_too_old} removed (older than {self.max_age} days)")
                    
                    # Save the updated JSON file with filtered IoCs
                    try:
                        with open(self.json_file, 'w') as f:
                            json.dump(json_iocs, f, indent=2)
                        logger.info(f"Saved updated IoCs to {self.json_file} after age filtering")
                    except Exception as e:
                        logger.error(f"Error saving filtered IoCs to JSON file: {str(e)}")
                
                # Display summary of age filtering
                if self.max_age > 0:
                    print(f"\nAge Filtering Summary (max age: {self.max_age} days):")
                    print(f"  Total IoCs: {total_iocs}")
                    print(f"  IoCs kept: {iocs_to_keep}")
                    print(f"  IoCs removed: {iocs_too_old}")
                
                # Create a dictionary of JSON IoCs for easier lookup
                json_ioc_dict = {f"{ioc['type']}:{ioc['id']}": ioc for ioc in all_json_iocs}
                
                # Find IoCs to add (in JSON but not in collection)
                iocs_to_add = []
                for ioc_key, ioc in json_ioc_dict.items():
                    if ioc_key not in collection_ioc_dict:
                        iocs_to_add.append(ioc)
                        # Calculate age in days
                        age_days = int((current_time - ioc.get("modified_date", 0)) / (24 * 60 * 60))
                        # Add to action table
                        self.action_table.add_row([
                            ioc["id"], 
                            ioc.get("name", "Unknown"),
                            datetime.fromtimestamp(ioc.get("modified_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("modified_date") else "Unknown",
                            age_days,
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
                            "Unknown",  # We don't have age info
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
    
    def display_ioc_status(self):
        """
        Load and display IoCs from JSON file and collection without updating.
        
        Returns:
            bool: True if successful, False otherwise
        """
        # Load IoCs from JSON file
        json_iocs = self.load_iocs_from_json()
        if not json_iocs:
            logger.error("Failed to load IoCs from JSON file")
            return False
        
        # Check if collection exists and get its ID
        url = f"{self.base_url}/intelligence/search"
        params = {
            "query": f'name:"{self.collection_name}" type:collection',
            "limit": 1
        }
        
        collection_exists = False
        
        try:
            # Search for the collection
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data') and len(data['data']) > 0:
                    self.collection_id = data['data'][0]['id']
                    logger.info(f"Found existing collection: {self.collection_id}")
                    collection_exists = True
                else:
                    logger.info(f"Collection does not exist: {self.collection_name}")
            else:
                logger.error(f"Error searching for collection: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception while checking collection: {str(e)}")
            return False
        
        # Create status table
        status_table = PrettyTable()
        status_table.field_names = ["IoC ID", "Type", "Name", "Last Modified", "Age (days)", "In Collection"]
        
        # Process each IoC type from JSON
        all_json_iocs = []
        current_time = datetime.now().timestamp()
        
        # Add files
        if "files" in json_iocs and json_iocs["files"]:
            for ioc in json_iocs["files"]:
                modified_date = ioc.get("modified_date", 0)
                age_days = int((current_time - modified_date) / (24 * 60 * 60)) if modified_date else "Unknown"
                all_json_iocs.append({
                    "type": "file",
                    "id": ioc["id"],
                    "name": ioc.get("name", "Unknown"),
                    "created_date": ioc.get("created_date", 0),
                    "modified_date": modified_date,
                    "age_days": age_days
                })
        
        # Add domains
        if "domains" in json_iocs and json_iocs["domains"]:
            for ioc in json_iocs["domains"]:
                modified_date = ioc.get("modified_date", 0)
                age_days = int((current_time - modified_date) / (24 * 60 * 60)) if modified_date else "Unknown"
                all_json_iocs.append({
                    "type": "domain",
                    "id": ioc["id"],
                    "name": ioc.get("name", "Unknown"),
                    "created_date": ioc.get("created_date", 0),
                    "modified_date": modified_date,
                    "age_days": age_days
                })
        
        # Add URLs
        if "urls" in json_iocs and json_iocs["urls"]:
            for ioc in json_iocs["urls"]:
                modified_date = ioc.get("modified_date", 0)
                age_days = int((current_time - modified_date) / (24 * 60 * 60)) if modified_date else "Unknown"
                all_json_iocs.append({
                    "type": "url",
                    "id": ioc["id"],
                    "name": ioc.get("name", "Unknown"),
                    "created_date": ioc.get("created_date", 0),
                    "modified_date": modified_date,
                    "age_days": age_days
                })
        
        # Add IPs
        if "ips" in json_iocs and json_iocs["ips"]:
            for ioc in json_iocs["ips"]:
                modified_date = ioc.get("modified_date", 0)
                age_days = int((current_time - modified_date) / (24 * 60 * 60)) if modified_date else "Unknown"
                all_json_iocs.append({
                    "type": "ip_address",
                    "id": ioc["id"],
                    "name": ioc.get("name", "Unknown"),
                    "created_date": ioc.get("created_date", 0),
                    "modified_date": modified_date,
                    "age_days": age_days
                })
        
        # Get collection IoCs if collection exists
        collection_iocs = {}
        if collection_exists:
            url = f"{self.base_url}/collections/{self.collection_id}/items"
            
            try:
                response = requests.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    collection_data = response.json()
                    for ioc in collection_data.get('data', []):
                        collection_iocs[f"{ioc['type']}:{ioc['id']}"] = ioc
                else:
                    logger.error(f"Error getting collection IoCs: {response.status_code} - {response.text}")
                    return False
            except Exception as e:
                logger.error(f"Exception while getting collection IoCs: {str(e)}")
                return False
        
        # Calculate age statistics
        too_old_count = 0
        if self.max_age > 0:
            too_old_count = sum(1 for ioc in all_json_iocs if isinstance(ioc["age_days"], int) and ioc["age_days"] > self.max_age)
        
        # Populate the status table
        for ioc in all_json_iocs:
            ioc_key = f"{ioc['type']}:{ioc['id']}"
            in_collection = "Yes" if ioc_key in collection_iocs else "No"
            
            # Determine if this IoC would be kept or removed based on age
            age_status = ""
            if self.max_age > 0 and isinstance(ioc["age_days"], int) and ioc["age_days"] > self.max_age:
                age_status = " (would be removed)"
            
            status_table.add_row([
                ioc["id"],
                ioc["type"],
                ioc["name"],
                datetime.fromtimestamp(ioc.get("modified_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if ioc.get("modified_date") else "Unknown",
                str(ioc["age_days"]) + age_status,
                in_collection
            ])
        
        # Display the table
        if status_table.rowcount > 0:
            print(f"\nIoC Status for collection: {self.collection_name}")
            print(f"Collection exists: {'Yes' if collection_exists else 'No'}")
            print(f"Total IoCs in JSON: {len(all_json_iocs)}")
            print(f"Total IoCs in Collection: {len(collection_iocs) if collection_exists else 'N/A'}")
            if self.max_age > 0:
                print(f"IoCs older than {self.max_age} days: {too_old_count} (would be removed if update is run)")
            print("\nIoC Details:")
            print(status_table)
        else:
            print("\nNo IoCs found in the JSON file.")
        
        return True


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Google Threat Intelligence IoC Updater')
    parser.add_argument('--collection-name', required=True, help='Name of the IoC collection')
    parser.add_argument('--api-key', required=True, help='Google Threat Intelligence API key')
    parser.add_argument('--status-only', action='store_true', help='Only display IoC status without updating')
    parser.add_argument('--max-age', type=int, default=0, help='Maximum age of IoCs in days (IoCs older than this will be removed, 0 means no removal)')
    
    return parser.parse_args()


def main():
    """
    Main function to run the script.
    """
    args = parse_arguments()
    
    logger.info(f"Starting IoC_Update for collection: {args.collection_name}")
    
    updater = IoC_Updater(
        api_key=args.api_key,
        collection_name=args.collection_name,
        max_age=args.max_age
    )
    
    if args.max_age > 0:
        logger.info(f"Age filtering enabled: IoCs older than {args.max_age} days will be removed")
    
    if args.status_only:
        logger.info("Status-only mode: Displaying IoC status without updating")
        if updater.display_ioc_status():
            logger.info("IoC status display completed successfully")
        else:
            logger.error("IoC status display encountered errors. Check the log for details.")
    else:
        if updater.create_collection_with_iocs():
            logger.info("IoC collection creation/update completed successfully")
            updater.display_action_table()
        else:
            logger.error("IoC collection creation/update encountered errors. Check the log for details.")


if __name__ == "__main__":
    main()
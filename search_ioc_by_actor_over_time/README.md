# VirusTotal Threat Actor Finder

## Overview

`search_ioc_by_actor_over_time.py` is a Python tool that queries the VirusTotal API to retrieve information about specific threat actors and their associated indicators of compromise (IOCs). The tool supports searching for threat actors modified within a specified time period, displays the results in formatted tables, and saves all data to a JSON file.

## Features

- Search for specific threat actors by name modified within a specified time period
- Fetch all associated IOCs (Files, IPs, URLs, and Domains)
- Display threat actor information in a formatted table
- Summarize IOCs by category (Files, IPs, URLs, Domains)
- Display the top 10 IOCs from each category with relevant details
- Save all data to a JSON file for further analysis
- Robust error handling and retry logic for API requests

## Requirements

- Python 3.6+
- `requests` library
- `tabulate` library
- A valid VirusTotal API key

## Installation

1. Clone this repository or download the script
2. Install the required Python packages:

```bash
pip install requests tabulate
Usage
./search_ioc_by_actor_over_time.py --api-key YOUR_API_KEY --actor-name "APT28" --time-period 24h
Command-line Arguments
ArgumentDescriptionDefault--api-keyYour VirusTotal API key (required)N/A--actor-nameName of the threat actor to search for (required)N/A--time-periodTime period for search (24h, 7d, 30d)24h--max-retriesMaximum number of retry attempts for API calls5--retry-delayInitial delay in seconds between retries5
Output
The script produces:

Threat Actor Information Table: Displays details about the threat actor including name, ID, last modified date, aliases, description, and country.
IOC Summary Table: Shows the count of IOCs by category (Files, IPs, URLs, Domains).
Top 10 IOC Tables: For each IOC category, displays the top 10 indicators with relevant information:

Files: SHA-256, type, size, first seen date
IPs: IP address, country, ASN owner, detection ratio
URLs: URL, detection ratio, first submission date
Domains: Domain name, creation date, detection ratio


JSON File: Saves all data to a JSON file named after the threat actor in an 'output' directory.

Example Output
=== Threat Actor Information ===
+-------------+--------------------------------------+-------------------------------+---------------------------+-----------------------------------------------------+---------+
| Name        | ID                                   | Last Modified                 | Aliases                   | Description                                         | Country |
+-------------+--------------------------------------+-------------------------------+---------------------------+-----------------------------------------------------+---------+
| APT28       | 09b06892-9738-5c53-b704-368d5ac8dd62 | 2025-04-10 14:32:21 UTC      | Fancy Bear, Sofacy, Sednit | Russian state-sponsored threat actor known for...   | Russia  |
+-------------+--------------------------------------+-------------------------------+---------------------------+-----------------------------------------------------+---------+

=== IOC Summary ===
+----------+-------+
| IOC Type | Count |
+----------+-------+
| FILES    | 245   |
| IPS      | 38    |
| URLS     | 127   |
| DOMAINS  | 42    |
+----------+-------+

=== Top 10 FILES ===
...

=== Top 10 IPS ===
...

=== Top 10 URLS ===
...

=== Top 10 DOMAINS ===
...

All data has been saved to output/apt28_threat_intel_20250415_143015.json
JSON Output Format
The JSON file includes:
json{
  "actor": {
    "id": "...",
    "attributes": {
      "name": "...",
      "aliases": [...],
      "description": "...",
      ...
    }
  },
  "iocs": {
    "files": [...],
    "ips": [...],
    "urls": [...],
    "domains": [...]
  },
  "summary": {
    "files": 245,
    "ips": 38,
    "urls": 127,
    "domains": 42
  }
}
Ignoring Output Files in Git
To prevent JSON output files from being uploaded to your repository, create a .gitignore file in the root of your project with the following content:
# Ignore all JSON files in the output directory
output/*.json

# Alternatively, ignore specific pattern of output files
# output/*_threat_intel_*.json
This will ensure that the output JSON files stay on your local machine and aren't committed to your Git repository.
Error Handling
The script includes robust error handling with:

Exponential backoff with jitter for retrying transient API errors
Detailed error messages to help diagnose issues
Partial results are returned if some data was collected before an error

Rate Limiting
This script respects VirusTotal's API rate limits by:

Adding delays between successful page fetches
Handling 429 (Too Many Requests) responses with proper retry logic
Using the Retry-After header when provided by the API

License
This project is available under the MIT License.
Disclaimer
This tool is intended for security research and threat intelligence purposes only. Always use responsibly and in compliance with applicable laws and regulations.
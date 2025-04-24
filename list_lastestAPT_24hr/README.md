# VirusTotal Threat Actor Retriever

A robust Python utility for fetching recently modified threat actor data from the VirusTotal API with error handling, pagination support, and resilient retry mechanisms.

## Overview

This script connects to the VirusTotal API to retrieve threat actors that have been modified within the last 24 hours. It's designed for security analysts, threat intelligence teams, and researchers who need to stay updated on the latest threat actor information.

## Features

- **Recent Threat Actor Retrieval**: Fetches threat actors modified in the last 24 hours
- **Robust Error Handling**: Comprehensive error detection and recovery
- **Pagination Support**: Automatically handles multi-page results
- **Exponential Backoff**: Implements retry logic with exponential backoff and jitter
- **Partial Results Preservation**: Returns collected data even if errors occur mid-retrieval
- **Secure API Key Handling**: Uses `getpass` to securely collect API credentials
- **Human-Readable Timestamps**: Converts UNIX timestamps to readable format

## Requirements

- Python 3.6+
- `requests` library
- VirusTotal API key with appropriate permissions

## Installation

1. Clone this repository:
   ```bash
   git clone https://gitlab.com/your-username/virustotal-threat-actor-retriever.git
   cd virustotal-threat-actor-retriever
   ```

2. Install required dependencies:
   ```bash
   pip install requests
   ```

## Usage

Run the script directly from the command line:

```bash
python3 list_lastestAPT_24hr.py.py
```

You will be prompted to enter your VirusTotal API key securely.

### Example Output

```
Fetching data from VirusTotal API (Filter: 'last_modification_date:1d+ collection_type:threat-actor')...
Attempting to fetch page 1...
  Page 1 Status Code: 200 (Attempt 1/5)
  Found 35 actors on this page. Total collected: 35
  Next cursor found, preparing for next page...
Attempting to fetch page 2...
  Page 2 Status Code: 200 (Attempt 1/5)
  Found 12 actors on this page. Total collected: 47
  No more pages found.

Fetched 47 threat actor(s) modified in the last 24 hours:
------------------------------------------------------------
Actor #1:
  Name: APT28
  ID: collection-threat-actor-aptxx
  Last Modified: 2025-04-15 18:22:30 UTC
------------------------------------------------------------
```

## Configuration

The main function `get_recent_threat_actors` accepts the following parameters:

- `api_key` (required): Your VirusTotal API key
- `max_retries` (optional, default=5): Maximum number of retry attempts for transient errors
- `initial_delay` (optional, default=5): Initial delay in seconds before the first retry

## Error Handling

The script handles various error conditions:
- Network connectivity issues
- API rate limiting
- Authentication failures
- Server errors
- JSON parsing errors

When errors occur during pagination, the script returns partial results collected before the error.

## Limitations

- Requires a valid VirusTotal API key with appropriate access level
- Subject to VirusTotal API rate limits 
- Currently filters for threat actors modified within the last 24 hours only

## License

[Your License Here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

This script uses the VirusTotal API v3.0.
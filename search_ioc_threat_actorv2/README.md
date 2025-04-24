# VirusTotal IOC Extractor

A Python utility for extracting all Indicators of Compromise (IOCs) associated with a specific threat actor from the VirusTotal API.

## Overview

This script connects to the VirusTotal API to retrieve comprehensive IOC data (files, IPs, URLs, and domains) associated with a specified threat actor. It handles pagination to collect all results, even when they exceed the API's per-request limit, and combines them into a single JSON output file.

## Features

- **Complete IOC Collection**: Extracts all files, IPs, URLs, and domains associated with a threat actor
- **Pagination Handling**: Automatically processes multiple result pages to ensure complete data collection
- **Robust Error Handling**: Implements retry logic with exponential backoff for temporary API failures
- **Progress Saving**: Saves intermediate results after processing each entity type
- **Comprehensive Reporting**: Provides a detailed summary of collected IOCs

## Requirements

- Python 3.6+
- `requests` library
- VirusTotal API key with appropriate permissions

## Installation

1. Clone this repository:
   ```bash
   git clone https://gitlab.com/your-username/virustotal-ioc-extractor.git
   cd virustotal-ioc-extractor
   ```

2. Install required dependencies:
   ```bash
   pip install requests
   ```

## Usage

Run the script with your VirusTotal API key:

```bash
python vt_ioc_extractor.py --api-key YOUR_API_KEY
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--api-key` | VirusTotal API key (required) | None |
| `--threat-id` | Threat actor UUID | 09b06892-9738-5c53-b704-368d5ac8dd62 |
| `--max-retries` | Maximum number of retry attempts for API calls | 5 |
| `--retry-delay` | Delay in seconds between retries | 5 |

### Example

```bash
python vt_ioc_extractor.py --api-key YOUR_API_KEY --threat-id 09b06892-9738-5c53-b704-368d5ac8dd62 --max-retries 3 --retry-delay 10
```

## Output

The script creates an `output` directory and saves the collected IOC data in a JSON file with the naming pattern:

```
output/threat-actor-{threat_id}.json
```

The JSON file contains:
- Files associated with the threat actor
- IP addresses associated with the threat actor
- URLs associated with the threat actor
- Domains associated with the threat actor
- Summary statistics about the collected IOCs

Example output structure:
```json
{
  "files": [ ... array of file objects ... ],
  "ips": [ ... array of IP objects ... ],
  "urls": [ ... array of URL objects ... ],
  "domains": [ ... array of domain objects ... ],
  "summary": {
    "files": 127,
    "ips": 43,
    "urls": 89,
    "domains": 36
  }
}
```

### Partial Results

If the script encounters errors during execution, it attempts to save partial results:
- After each entity type: `output/threat-actor-{threat_id}_progress.json`
- If a fatal error occurs: `output/threat-actor-{threat_id}_incomplete.json`

## Workflow

1. The script connects to the VirusTotal API
2. For each IOC type (file, IP, URL, domain):
   - Fetches all pages of results using cursor-based pagination
   - Saves progress after completing each entity type
3. Combines all collected IOCs into a single JSON file
4. Displays summary information about the collected IOCs

## Error Handling

The script implements comprehensive error handling:
- API rate limiting with exponential backoff
- Temporary service unavailability
- Network connectivity issues
- Unexpected API responses
- Progress saving to preserve partial results

## Limitations

- Requires a valid VirusTotal API key
- Subject to VirusTotal API rate limits
- Performance dependent on the number of IOCs associated with the threat actor

## License

[Your License Information Here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

This script uses the VirusTotal API v3.
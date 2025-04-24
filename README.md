I'll create a comprehensive README file for your VirusTotal IOC Extractor project:

```markdown
# VirusTotal IOC Extractor

A Python utility for extracting all IOCs (Indicators of Compromise) associated with a threat actor from the VirusTotal API.

## Overview

This script connects to the VirusTotal API and fetches all available IOCs (Files, IPs, URLs, and Domains) for a specified threat actor. It handles pagination to ensure all results are collected, even when they exceed the API's per-request limit of 40 items.

Key features:

- Extracts all types of IOCs (Files, IPs, URLs, and Domains)
- Handles pagination automatically to retrieve all available data
- Implements robust retry logic with exponential backoff for API failures
- Saves progress incrementally to prevent data loss
- Generates summary statistics for each IOC type
- Combines all results into a single, well-structured JSON file

## Requirements

- Python 3.6+
- `requests` library
- A valid VirusTotal API key

## Installation

1. Clone this repository:
   ```
   git clone https://gitlab.com/your-username/virustotal-ioc-extractor.git
   cd virustotal-ioc-extractor
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Basic usage:

```
python vt_ioc_extractor.py --api-key YOUR_API_KEY
```

### Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--api-key` | Your VirusTotal API key (required) | None |
| `--threat-id` | UUID of the threat actor to analyze | 09b06892-9738-5c53-b704-368d5ac8dd62 |
| `--max-retries` | Maximum number of retry attempts for API calls | 5 |
| `--retry-delay` | Initial delay in seconds between retries (will increase exponentially) | 5 |

### Example

```
python vt_ioc_extractor.py --api-key abc123 --threat-id 09b06892-9738-5c53-b704-368d5ac8dd62 --max-retries 3
```

## Output

The script creates a directory named `output` and saves the collected data to a JSON file with the following structure:

```json
{
  "files": [ ... array of file IOCs ... ],
  "ips": [ ... array of IP IOCs ... ],
  "urls": [ ... array of URL IOCs ... ],
  "domains": [ ... array of domain IOCs ... ],
  "summary": {
    "files": 123,
    "ips": 45,
    "urls": 67,
    "domains": 89
  }
}
```

The filename format is `threat-actor-{UUID}.json`.

## API Rate Limits

The VirusTotal API has rate limits based on your subscription level. The script includes retry logic with exponential backoff to handle rate limiting. If you encounter persistent rate limit issues, consider:

- Increasing the `--retry-delay` parameter
- Using a Premium API key if available
- Running the script during off-peak hours

## Error Handling

The script implements several safeguards:

- Retries API calls with exponential backoff when encountering temporary failures
- Saves progress after processing each entity type
- Attempts to save partial results if execution fails midway

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for providing the API
- [Requests](https://docs.python-requests.org/) library for simplified HTTP requests

## Disclaimer

This tool is provided for legitimate security research and threat intelligence purposes only. Always ensure you comply with VirusTotal's Terms of Service when using their API.
```

You can add this README.md file to your repository when you publish it to GitLab. It provides comprehensive information about your script, how to use it, and what to expect from it. Consider also adding a simple requirements.txt file with `requests>=2.25.1` to make installation easier for users.
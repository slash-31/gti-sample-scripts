# Google Threat Intelligence Interactive Vulnerability Explorer

An interactive Python utility for exploring and analyzing recent vulnerabilities from Google Threat Intelligence.

## Overview

This script provides a convenient command-line interface for security analysts and vulnerability management teams to explore vulnerabilities that have been recently added or updated in Google Threat Intelligence. It presents a curated list of the most recent vulnerabilities and allows users to interactively examine detailed information about each one.

## Features

- **Recent Vulnerability Data**: Fetches vulnerabilities modified or added in the last 24 hours
- **Interactive Exploration**: Select specific vulnerabilities to examine in detail
- **Comprehensive Details**: Displays risk ratings, exploitation status, CVSS scores, affected products, and more
- **Reference Links**: Lists sources and additional information for each vulnerability
- **Robust Error Handling**: Implements retry logic with exponential backoff and jitter
- **Human-Readable Formatting**: Presents data in clear, easy-to-read tables and formatted text

## Requirements

- Python 3.6+
- Google Threat Intelligence API key (Enterprise or Enterprise Plus license required)
- Required Python packages:
  - `requests`
  - `tabulate`
  - `textwrap` (standard library)

## Installation

1. Clone this repository:
   ```bash
   git clone https://gitlab.com/your-username/gti-vulnerability-explorer.git
   cd gti-vulnerability-explorer
   ```

2. Install required dependencies:
   ```bash
   pip install requests tabulate
   ```

## Usage

Run the script directly:

```bash
python gti_interactive_vuln_explorer_loop.py
```

You'll be prompted to enter your Google Threat Intelligence API key securely.

### Interactive Workflow

1. The script fetches and displays the top 10 most recently modified/added vulnerabilities
2. Enter a number (1-10) to explore a specific vulnerability in detail
3. The script retrieves and displays comprehensive information including:
   - Basic vulnerability details (ID, name, risk rating)
   - CVSS scores (v2.0 and v3.x)
   - Creation and modification dates
   - Full description
   - Affected products
   - External references
   - Associated tags
4. After viewing the details, you can select another vulnerability or type 'end' to exit

## Example Output

Initial vulnerability list:
```
--- Top 10 Google TI Vulnerabilities (Updated/Added Last 24 Hours as of 2025-04-16 10:30:45 UTC) ---
+---+------------------------+------------+--------+---------------------------+
| # | ID / Name              | Risk       | CVSSv3 | Last Modified (UTC)       |
+===+========================+============+========+===========================+
| 1 | CVE-2025-1234          | Critical   | 9.8    | 2025-04-15 18:22:30       |
+---+------------------------+------------+--------+---------------------------+
| 2 | CVE-2025-5678          | High       | 8.4    | 2025-04-15 15:47:12       |
+---+------------------------+------------+--------+---------------------------+
| 3 | CVE-2025-9012          | Medium     | 6.5    | 2025-04-15 12:05:46       |
+---+------------------------+------------+--------+---------------------------+
```

Detailed vulnerability information:
```
============================================================
 Google TI Vulnerability Details: CVE-2025-1234
============================================================
  ID: collection-vuln-cve-2025-1234
  Risk Rating: Critical
  Exploitation State: Exploited in the Wild
  Creation Date: 2025-04-14 09:15:22 UTC
  Last Modified: 2025-04-15 18:22:30 UTC

  --- CVSS Scores ---
  CVSS v3.x Base Score: 9.8
  CVSS v3.x Temporal Score: 9.2
  CVSS v2.0 Base Score: 10.0
  CVSS v2.0 Temporal Score: 9.5

  --- Description ---
  A remote code execution vulnerability in Example Product allows an
  unauthenticated attacker to execute arbitrary code on the affected system
  via a specially crafted HTTP request. This vulnerability requires no user
  interaction and can be exploited over the network.

  --- Affected Products (Sample) ---
  - Vendor: Example Corp, Product: Example Product, Version: 2.0-2.5
  - Vendor: Example Corp, Product: Example Product Pro, Version: 1.8-2.2
  ... and 3 more.

  --- References ---
  - https://example.com/security/advisory/cve-2025-1234
  - https://nvd.nist.gov/vuln/detail/CVE-2025-1234
  - https://example-corp.com/security/patches/april-2025

  --- Tags ---
  rce, critical, network, unauthenticated, example-corp
============================================================
```

## Limitations

- Requires a Google Threat Intelligence API key with Enterprise or Enterprise Plus license
- Subject to API rate limits and quotas
- Only fetches vulnerabilities modified or added within the last 24 hours
- Displays a maximum of 10 vulnerabilities in the initial list

## License

[Your License Information Here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- This script uses the Google Threat Intelligence API via VirusTotal's API endpoint
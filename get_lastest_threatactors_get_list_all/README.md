# Google Threat Intelligence Interactive Threat Actor Explorer

An interactive Python utility for exploring recently modified threat actors from Google Threat Intelligence, their relationships, and associated IOCs.

## Overview

This script provides security analysts and threat intelligence teams with an interactive command-line interface to explore the most recently modified threat actors in Google Threat Intelligence. It fetches, displays, and saves comprehensive information about threat actors, their related entities (reports, campaigns, vulnerabilities), and associated indicators of compromise (IOCs).

## Features

- **Real-time Threat Actor Data**: Fetches threat actors modified in the last 24 hours
- **Comprehensive Relationship Mapping**: Retrieves related reports, campaigns, and vulnerabilities for selected actors
- **IOC Collection**: Gathers associated files, URLs, domains, and IP addresses
- **Interactive Exploration**: Allows selecting specific actors to examine in detail
- **Recency Highlighting**: Visually highlights items updated within the last 24 hours
- **Automatic Data Persistence**: Saves all exploration results to JSON files upon exit
- **Robust Error Handling**: Implements retry logic with exponential backoff and jitter
- **Human-Readable Output**: Formats data in clear, easy-to-read tables

## Requirements

- Python 3.6+
- Google Threat Intelligence API key (Enterprise or Enterprise Plus license required)
- Required Python packages:
  - `requests`
  - `tabulate`

## Installation

1. Clone this repository:
   ```bash
   git clone https://gitlab.com/your-username/gti-threat-actor-explorer.git
   cd gti-threat-actor-explorer
   ```

2. Install required dependencies:
   ```bash
   pip install requests tabulate
   ```

## Usage

Run the script directly:

```bash
python get_latest_threatactors_get_list_all.py
```

You can also set your API key as an environment variable:

```bash
export GTI_API_KEY=your_api_key_here
python get_latest_threatactors_get_list_all.py
```

### Interactive Workflow

1. The script fetches and displays the top 5 most recently modified threat actors
2. You'll see the total count of actors modified in the last 24 hours
3. Enter a number (1-5) to explore a specific actor
4. The script retrieves and displays:
   - Related reports (sorted by creation date)
   - Related campaigns (sorted by last modification date)
   - Related vulnerabilities (sorted by last modification date)
   - Associated IOCs (files, URLs, domains, IP addresses) - sorted by recency
5. After viewing the details, you can select another actor or type 'end' to exit
6. All exploration data is saved to a timestamped JSON file in the "output" directory

## Output Example

```
--- Top 5 Google TI Threat Actors (Updated Last 24 Hours as of 2025-04-16 10:30:45 UTC) ---
+---+----------------+---------------------------+--------------------+
| # | Name           | Last Modified (UTC)       | ID                 |
+===+================+===========================+====================+
| 1 | APT28          | 2025-04-15 18:22:30      | collection-apt28   |
+---+----------------+---------------------------+--------------------+
| 2 | BlackCat       | 2025-04-15 15:47:12      | collection-alphv   |
+---+----------------+---------------------------+--------------------+
| 3 | Sandworm Team  | 2025-04-15 12:05:46      | collection-sandr   |
+---+----------------+---------------------------+--------------------+
| 4 | UNC2452        | 2025-04-15 09:33:18      | collection-unc2452 |
+---+----------------+---------------------------+--------------------+
| 5 | FIN7           | 2025-04-15 02:49:57      | collection-fin7    |
+---+----------------+---------------------------+--------------------+

[*] Total unique threat actors modified in the last 24 hours: 43
```

## Data Saved

The script saves all exploration data to timestamped JSON files in the "output" directory:

```
output/gti_actor_exploration_20250416_103045.json
```

The JSON file includes:
- Session information (timestamp, initial actors presented, total count)
- Detailed information for each explored actor
- All relationships and IOCs fetched during the session

## Limitations

- Requires a Google Threat Intelligence API key with Enterprise or Enterprise Plus license
- Subject to API rate limits and quotas
- Only fetches threat actors modified in the last 24 hours
- Displays a maximum of 5 actors in the initial list
- Limits results to the top 15 relationships per type and 10 IOCs per type

## License

[Your License Information Here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- This script uses the Google Threat Intelligence API via VirusTotal's API endpoint
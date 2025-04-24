# VirusTotal IoC Management System

This project consists of two Python scripts for managing Indicators of Compromise (IoCs) using the VirusTotal API:

1. **IoC_Pull.py**: Retrieves the latest IoCs for a specified threat actor and maintains a JSON file.
2. **IoC_Update.py**: Synchronizes the JSON file with a VirusTotal IoC collection.

## System Flow Diagram

![IoC Management System Flow Diagram](./ioc-flow-diagram.svg)

## Features

- Retrieve top IoCs for a specified threat actor
- Store IoCs in a local JSON file (IoC_active.json)
- Manage IoCs in a remote IoC collection
- Log all operations (add/update/delete) in XML format
- Automatically handle IoC lifecycle management
- Retry logic for API calls

## Requirements

- Python 3.6+
- `requests` library
- `prettytable` library

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/virustotal-ioc-management.git
cd virustotal-ioc-management
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### IoC_Pull.py

This script retrieves the latest IoCs for a threat actor and updates the JSON file.

```bash
python IoC_Pull.py --threat-actor-id <uuid> --api-key <key> [--limit <limit>] [--max-retries <retries>] [--retry-delay <seconds>]
```

#### Arguments

- `--threat-actor-id`: UUID of the threat actor to retrieve IoCs for
- `--api-key`: VirusTotal API key
- `--limit`: (Optional) Maximum number of IoCs to retrieve per type (default: 20)
- `--max-retries`: (Optional) Maximum number of retry attempts for API calls (default: 5)
- `--retry-delay`: (Optional) Delay in seconds between retries (default: 5)

#### Example
```bash
python IoC_Pull.py --threat-actor-id 550e8400-e29b-41d4-a716-446655440000 --api-key YOUR_API_KEY
```

### IoC_Update.py

This script synchronizes the IoC collection with the JSON file.

```bash
python IoC_Update.py --collection-name <name> --api-key <key>
```

#### Arguments

- `--collection-name`: Name of the IoC collection to manage
- `--api-key`: VirusTotal API key

#### Example
```bash
python IoC_Update.py --collection-name APT29_Collection --api-key YOUR_API_KEY
```

#### Setting up as a Cron Job

To run IoC_Update.py every 5 minutes:
```
*/5 * * * * /path/to/python /path/to/IoC_Update.py --collection-name APT29_Collection --api-key YOUR_API_KEY
```

## How It Works

### IoC_Pull.py

1. **IoC Retrieval**:
   - Connects to VirusTotal API
   - Searches for IoCs related to the specified threat actor
   - Retrieves details including ID, type, name, and dates
   - Implements retry logic for handling API rate limits

2. **JSON Management**:
   - Loads existing IoCs from IoC_active.json (if it exists)
   - Compares existing IoCs with newly retrieved ones
   - Identifies new, updated, and removed IoCs
   - Updates the JSON file accordingly

3. **Logging**:
   - Records all actions in XML format
   - Includes timestamps and detailed information
   - Saves logs to IoC_Logs.xml

### IoC_Update.py

1. **Collection Verification**:
   - Checks if the specified IoC collection exists
   - Creates the collection if necessary

2. **Synchronization**:
   - Loads IoCs from IoC_active.json
   - Retrieves current IoCs from the collection
   - Compares the two sets to identify differences
   - Displays an action table of changes

3. **Collection Management**:
   - Adds new IoCs to the collection
   - Removes IoCs from the collection that are not in the JSON file

4. **Logging**:
   - Records all actions in XML format
   - Includes timestamps and detailed information
   - Saves logs to IoC_Logs.xml

## JSON File Structure

The IoC_active.json file uses the following structure:

```json
{
  "files": [
    {
      "id": "3395856ce81f2b7382dee72602f798b642f14140",
      "type": "file",
      "name": "malware.exe",
      "created_date": 1619712000,
      "modified_date": 1650734400,
      "threat_actor_id": "550e8400-e29b-41d4-a716-446655440000"
    }
  ],
  "ips": [
    {
      "id": "192.168.1.1",
      "type": "ip",
      "name": "192.168.1.1",
      "created_date": 1619712000,
      "modified_date": 1650734400,
      "threat_actor_id": "550e8400-e29b-41d4-a716-446655440000"
    }
  ],
  "urls": [],
  "domains": [
    {
      "id": "evil.com",
      "type": "domain",
      "name": "evil.com",
      "created_date": 1619712000,
      "modified_date": 1650734400,
      "threat_actor_id": "550e8400-e29b-41d4-a716-446655440000"
    }
  ]
}
```

## Log File Structure

The IoC_Logs.xml file uses the following XML structure:

```xml
<log_entry>
  <timestamp>2025-04-23 10:15:30</timestamp>
  <level>INFO</level>
  <message>Added IoC to collection: domain:evil.com - evil.com</message>
</log_entry>
<log_entry>
  <timestamp>2025-04-23 10:15:31</timestamp>
  <level>INFO</level>
  <message>Deleted IoC from collection: file:3395856ce81f2b7382dee72602f798b642f14140 - malware.exe</message>
</log_entry>
```

## API References

The scripts use the following VirusTotal API endpoints:

- **Search Collections**: `https://www.virustotal.com/api/v3/intelligence/search`
- **Collection Items**: `https://www.virustotal.com/api/v3/collections/{collection_id}/items`
- **Create Collection**: `https://www.virustotal.com/api/v3/collections`
- **Collection Search**: `https://www.virustotal.com/api/v3/collections/threat-actor--{threat_actor_id}/search`

## Troubleshooting

- Check the log file IoC_Logs.xml for detailed information about any errors.
- Ensure your API key has the necessary permissions for the required operations.
- Verify network connectivity to the VirusTotal API endpoints.
- For rate limiting issues, adjust the `--max-retries` and `--retry-delay` parameters.

## License

This software, including all associated scripts, documentation, and other materials (collectively, the "Software"), is provided solely for demonstration and laboratory purposes. The Software is not intended for, and must not be deployed in, production environments.

The Software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the Software or the use or other dealings in the Software.

VirusTotal and its affiliates, subsidiaries, officers, directors, employees, and agents expressly disclaim all liability for any costs, fees, expenses, or damages incurred by any party resulting from the use of this Software, including but not limited to API usage fees, computing costs, storage costs, and any other charges that may be incurred through the operation of this Software.

By using this Software, you acknowledge and agree that you have read this notice, understand it, and agree to be bound by its terms.

THIS SOFTWARE IS NOT SUPPORTED BY VIRUSTOTAL OR ITS AFFILIATES. USE AT YOUR OWN RISK.
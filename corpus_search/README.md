# GTI Enterprise Submission Hunter

A CLI tool for auditing your organization's file submission history on [Google Threat Intelligence](https://www.virustotal.com/) (GTI / VirusTotal). It identifies every file uploaded by your group to the public corpus, attributes each submission to a specific API key via its unique `source_key`, verifies data exclusivity, and exports the results for auditing.

## What It Does

1. **Group-Scoped Search** — Queries `/intelligence/search` with `submitter:me` to retrieve all files submitted by anyone in your VT group, filtered by date range via `fs:` (first-submission) modifiers.

2. **Per-Submitter Attribution** — For each file, fetches `/files/{hash}/submissions` to extract the `source_key` — a unique identifier stamped on every submission that maps to a specific API key. This lets you determine exactly *who* (which key) submitted each file.

3. **Automated Pagination** — The API returns a maximum of 300 results per request. The script automatically manages cursors to loop through your entire history without manual intervention.

4. **Exclusivity Verification** — For every file found, the script checks the `unique_sources` attribute. If `unique_sources == 1`, the file is flagged as **Exclusive**, meaning only one entity has submitted that file to VirusTotal. With the `--exclusive` flag, non-exclusive files are filtered out.

5. **Data Extraction** — For each file the script pulls:
   - SHA-256 and MD5 hashes
   - File type description and meaningful filename
   - Submission date, first-submission date
   - `source_key` of the submitter (unique per API key)
   - All `source_keys` that have submitted the file
   - Submission interface (api/web), country, and city
   - Unique source count and total submission count

6. **Optional Source Key Filtering** — Pass `--source-key <key>` to filter results to a specific submitter's API key. Omit it to see all group submissions with attribution.

7. **Multi-Format Reporting**:
   - **Terminal** — Live progress counter, top-10 data preview, file-type breakdown, source_key breakdown (who submitted the most files), exclusive count, and grand total.
   - **CSV** — Full dataset for long-term auditing or integration into security tools.

8. **Resilient API Handling** — Retry logic with exponential backoff and jitter for 429 (rate-limit) and 5xx (server error) responses. Partial results are preserved if pagination is interrupted.

## Source Key Discovery

Each API key has a unique `source_key` — an 8-character hex identifier that VT stamps on every submission. Use `--discover-key` to automatically find yours:

```bash
python gti_hunter.py -k YOUR_API_KEY --discover-key
```

This submits a small probe file, waits for indexing, and displays your key info:

```
### YOUR API KEY INFO ###
+----------------------+----------------------------+
| Field                | Value                      |
+======================+============================+
| source_key           | 324a3038                   |
+----------------------+----------------------------+
| user_id              | jsmith                     |
+----------------------+----------------------------+
| group                | example_com                |
+----------------------+----------------------------+
| group_users          | 11                         |
+----------------------+----------------------------+
| submission_interface | api                        |
+----------------------+----------------------------+
| submission_country   | US                         |
+----------------------+----------------------------+
| submission_city      | new york                   |
+----------------------+----------------------------+
| api_key_prefix       | a32c8680...                |
+----------------------+----------------------------+
```

Once you know your `source_key`, use `--source-key` to filter audit results to just your submissions.

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.10+** | Uses modern syntax. |
| **`requests`** | HTTP client for the VirusTotal API. |
| **`tabulate`** | Terminal table formatting. |
| **GTI Enterprise API Key** | Must have Intelligence Search permissions. Standard "Public API" keys will **not** work. |

### Install Dependencies

```bash
pip install requests tabulate
```

### Network Requirements

- HTTPS connectivity to `https://www.virustotal.com` over port 443.
- If behind a corporate proxy, set the `HTTPS_PROXY` environment variable.

### API Quota

Each page of 300 results consumes one Intelligence Search credit. Additionally, each file requires one API call to `/files/{hash}/submissions` for source_key attribution.

## Usage

```bash
python gti_hunter.py -k <API_KEY> -s <START_DATE> -e <END_DATE> [options]
python gti_hunter.py -k <API_KEY> --discover-key
```

### CLI Arguments

| Short | Long | Required | Description |
|---|---|---|---|
| `-k` | `--key` | Yes | Your GTI / VirusTotal Enterprise API key |
| `-s` | `--start` | Yes* | Start date in `YYYY-MM-DD` format |
| `-e` | `--end` | Yes* | End date in `YYYY-MM-DD` format |
| `-o` | `--output` | No | Output CSV filename (default: `my_submissions.csv`) |
| `-l` | `--limit` | No | Cap the total number of matched results |
| `-x` | `--exclusive` | No | Only return files where `unique_sources == 1` |
| | `--source-key` | No | Filter to a specific submitter's source_key |
| | `--discover-key` | No | Discover your API key's source_key and exit |

\* Not required when using `--discover-key`.

### Examples

```bash
# Discover your source_key
python gti_hunter.py -k YOUR_API_KEY --discover-key

# Audit all group submissions for the last 6 months
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30

# Filter to a specific submitter's source_key
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30 --source-key 324a3038

# Only exclusive files, saved to a named CSV
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30 -x -o exclusive_audit.csv

# Cap results at 500
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30 -l 500
```

## Expected Output

### Terminal — Progress

```
[*] User: jsmith  |  Email: jsmith@example.com
[*] Group: example_com  |  Org: Example Corp
[*] Group 'example_com' has 11 users.

[*] Searching group submissions: submitter:me fs:2025-01-01+ fs:2025-06-30-
[*] Showing ALL group submissions with source_key attribution
[*] Approximately 192 files in date range...
[+] Checked 10 files, 10 matched...
[+] Checked 20 files, 20 matched...
...
[+] Checked 192 files, 192 matched...
```

### Terminal — Source Key Breakdown

```
### SUBMISSIONS BY SOURCE_KEY ###
+--------------+---------+
| source_key   | Files   |
+--------------+---------+
| 324a3038     |      45 |
| f7a31e41     |      38 |
| 20f3cdee     |      12 |
| ...          |     ... |
+--------------+---------+
```

### Terminal — Grand Totals

```
[!] Exclusive Files (unique_sources == 1): 123
[!] Grand Total: 192
[!] Unique Submitters (source_keys): 671
[!] CSV File Saved: my_submissions.csv
```

### CSV Output

The output file contains one row per file with the following columns:

| Column | Description |
|---|---|
| `sha256` | SHA-256 hash (primary identifier) |
| `md5` | MD5 hash |
| `filename` | Original filename (VirusTotal's "meaningful name") |
| `type` | File type description (e.g., Android, Win32 EXE, PDF) |
| `exclusive_to_me` | `YES` if only one submitter, `NO` otherwise |
| `unique_sources` | Number of distinct entities that have submitted this file |
| `total_submissions` | Total number of times the file has been submitted |
| `submission_date` | Submission date for the matched source_key (UTC) |
| `first_submission_date` | Global first submission date on VT (UTC) |
| `source_key` | 8-char hex ID of the submitter's API key |
| `all_source_keys` | Comma-separated list of all source_keys for this file |
| `submission_interface` | How the file was submitted (`api`, `web`, etc.) |
| `submission_country` | Country of the submitter |
| `submission_city` | City of the submitter |

## API Endpoints Used

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v3/users/{api_key}` | `GET` | Resolve user ID and email for the API key |
| `/api/v3/users/{id}/groups` | `GET` | Discover the user's VT group/organization |
| `/api/v3/groups/{id}/users` | `GET` | List all users in the group |
| `/api/v3/intelligence/search` | `GET` | Search the public corpus with `submitter:me` + date filters |
| `/api/v3/files/{hash}/submissions` | `GET` | Get per-submission source_key attribution for each file |

## Error Handling

- **Rate Limits (429)** — Automatically retries with exponential backoff, respecting `Retry-After` headers when present.
- **Server Errors (5xx)** — Retried up to 5 times with increasing delays.
- **Client Errors (4xx)** — Non-retryable errors (400, 401, 403) fail immediately with a descriptive message.
- **Network Failures** — Connection errors and timeouts are retried with the same backoff strategy.
- **Partial Results** — If pagination is interrupted, the script saves whatever data was collected before the failure.
- **Invalid Dates** — Validates date format (`YYYY-MM-DD`) and ordering (start <= end) before making any API calls.

## License

MIT — see the root repository for details.

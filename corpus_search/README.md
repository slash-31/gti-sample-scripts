# GTI Enterprise Submission Hunter

A CLI tool for auditing your own file submission history on [Google Threat Intelligence](https://www.virustotal.com/) (GTI / VirusTotal). It performs a high-volume, automated search of the VirusTotal Intelligence database to identify every file uploaded using your specific API key, verify data exclusivity within the global corpus, and export the results for long-term auditing.

## What It Does

1. **Identity-Filtered Search** — Uses the `submitter:me` query modifier to ensure results are strictly limited to files you (or your automated systems) have uploaded, scoped to a date range via `fs:` (first-submission) filters.

2. **Automated Pagination** — The API returns a maximum of 300 results per request. The script automatically manages cursors to loop through your entire history (e.g., thousands of files) without manual intervention.

3. **Exclusivity Verification** — For every file found, the script checks the `unique_sources` attribute. If `unique_sources == 1`, the file is flagged as **Exclusive**, meaning you are the only entity in the world that has submitted that file to VirusTotal. With the `--exclusive` flag, the script filters results to **only** return exclusive files — both server-side (via the `unique_sources:1` query modifier) and client-side as a safety net.

4. **Data Extraction** — For each file the script pulls:
   - SHA-256 hash
   - MD5 hash
   - File type description
   - Meaningful name (original filename)
   - First submission date (human-readable)
   - Unique source count
   - Total submission count

5. **Multi-Format Reporting**:
   - **Terminal** — Live progress counter during pagination, a top-10 data preview table, a file-type summary breakdown (e.g., how many APKs vs. EXEs), exclusive file count, and grand total.
   - **CSV** — Full dataset saved to a local spreadsheet for long-term auditing or integration into other security tools.

6. **Resilient API Handling** — Retry logic with exponential backoff and jitter for 429 (rate-limit) and 5xx (server error) responses. Partial results are preserved if pagination is interrupted.

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.x** | Any modern Python 3 version. |
| **`requests`** | HTTP client for the VirusTotal API. |
| **`tabulate`** | Terminal table formatting. |
| **GTI Enterprise API Key** | Must have Intelligence Search permissions. Standard "Public API" keys will **not** work with the `/intelligence/search` endpoint. |

### Install Dependencies

```bash
pip install requests tabulate
```

### Network Requirements

- HTTPS connectivity to `https://www.virustotal.com` over port 443.
- If behind a corporate proxy, set the `HTTPS_PROXY` environment variable.

### API Quota

Each page of 300 results consumes one Intelligence Search credit. For example, ~3,700 files would use approximately 13 search credits from your monthly allowance.

## Usage

```bash
python gti_hunter.py -k <API_KEY> -s <START_DATE> -e <END_DATE> [-o <OUTPUT_FILE>] [-l <LIMIT>] [-x]
```

### CLI Arguments

| Short | Long | Required | Description |
|---|---|---|---|
| `-k` | `--key` | Yes | Your GTI / VirusTotal Enterprise API key |
| `-s` | `--start` | Yes | Start date in `YYYY-MM-DD` format |
| `-e` | `--end` | Yes | End date in `YYYY-MM-DD` format |
| `-o` | `--output` | No | Output CSV filename (default: `my_submissions.csv`) |
| `-l` | `--limit` | No | Cap the total number of results fetched |
| `-x` | `--exclusive` | No | Only return files where you are the sole submitter (`unique_sources == 1`) |

### Examples

```bash
# Audit the last 6 months of submissions
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30

# Only return files exclusively submitted by you
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30 -x

# Save to a specific file
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30 -o audit_q1_q2.csv

# Combine: exclusive files only, saved to a named CSV
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30 -x -o exclusive_audit.csv

# Fetch only the first 500 results
python gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-06-30 -l 500
```

## Expected Output

### Terminal — Progress

```
[*] Querying GTI for: submitter:me fs:2025-01-01+ fs:2025-06-30-    # without -x
[*] Querying GTI for: submitter:me fs:2025-01-01+ fs:2025-06-30- unique_sources:1  # with -x
[*] Approximately 3686 total files found.
[+] Downloaded 300 records...
[+] Downloaded 600 records...
[+] Downloaded 900 records...
...
[+] Downloaded 3686 records...
```

### Terminal — Data Preview (Top 10)

```
### DATA PREVIEW (Top 10) ###
+-----------+----------+------------------+--------+----------------+----------------+-------------------+---------------------+
| sha256    | md5      | filename         | type   | exclusive_to_me| unique_sources | total_submissions  | submission_date     |
+-----------+----------+------------------+--------+----------------+----------------+-------------------+---------------------+
| a1b2c3... | d4e5f6...| malware.apk      | APK    | YES            | 1              | 1                  | 2025-03-15 08:22:41 |
| f7e8d9... | c0b1a2...| trojan.exe       | PE32   | NO             | 4              | 12                 | 2025-02-01 14:05:33 |
| ...       | ...      | ...              | ...    | ...            | ...            | ...                | ...                 |
+-----------+----------+------------------+--------+----------------+----------------+-------------------+---------------------+
```

### Terminal — File Type Summary

```
### SUBMISSION SUMMARY BY TYPE ###
+---------------------+-------+
| File Type           | Count |
+---------------------+-------+
| APK                 |  1842 |
| PE32 executable     |   956 |
| PDF document        |   412 |
| ELF                 |   276 |
| unknown             |   200 |
+---------------------+-------+
```

### Terminal — Grand Totals

```
[!] Exclusive Files (Only you submitted): 1523
[!] Grand Total Extracted: 3686
[!] CSV File Saved: my_submissions.csv
```

### CSV Output

The output file contains one row per file with the following columns:

| Column | Description |
|---|---|
| `sha256` | SHA-256 hash (primary identifier) |
| `md5` | MD5 hash |
| `filename` | Original filename (VirusTotal's "meaningful name") |
| `type` | File type description (e.g., APK, PE32, PDF) |
| `exclusive_to_me` | `YES` if you are the only submitter, `NO` otherwise |
| `unique_sources` | Number of distinct entities that have submitted this file |
| `total_submissions` | Total number of times the file has been submitted |
| `submission_date` | Date of first submission (UTC, `YYYY-MM-DD HH:MM:SS`) |

## API Endpoint Used

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v3/intelligence/search` | `GET` | Search the VirusTotal Intelligence corpus with `submitter:me` filter |

## Error Handling

- **Rate Limits (429)** — Automatically retries with exponential backoff, respecting `Retry-After` headers when present.
- **Server Errors (5xx)** — Retried up to 5 times with increasing delays.
- **Network Failures** — Connection errors and timeouts are retried with the same backoff strategy.
- **Partial Results** — If pagination is interrupted after some pages have been fetched, the script saves whatever data was collected before the failure.
- **Invalid Dates** — The script validates date format (`YYYY-MM-DD`) and ordering (start <= end) before making any API calls.

## License

MIT — see the root repository for details.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A collection of standalone Python CLI scripts for querying the Google Threat Intelligence (GTI) / VirusTotal v3 API. Each script lives in its own directory and handles a specific threat intelligence workflow (fetching IoCs, threat actors, vulnerabilities, malware samples, etc.).

**All scripts require a valid GTI/VirusTotal API key** passed via CLI argument (`-k`/`--key` or `--api-key`). Some features require Enterprise or Enterprise Plus licences.

## Repository Structure

Each subdirectory is an independent script with its own README:
- `corpus_search/` — Hunt for files submitted by your API key in a date range (exports CSV)
- `gti_search_last24h_malware/` — Fetch Categorised Threat Lists (ransomware, phishing, etc.) with filters and sample download
- `gti_update_ioc_collection/` — Two-script IoC lifecycle system: pull IoCs for a threat actor, then sync to a VT collection
- `gti_interactive_vuln_explorer_loop/` — Interactive REPL for exploring recent vulnerabilities
- `search_ioc_by_actor_over_time/` — Fetch IoCs for a named threat actor filtered by time period
- `search_ioc_threat_actorv2/`, `get_lastest_threatactors_get_list_all/`, `list_lastestAPT_24hr/`, `latest_threatactor_24hr_fulllookup/` — Various threat actor listing/lookup scripts

## Running Scripts

```bash
# Install dependencies (root-level covers most scripts)
pip install -r requirements.txt

# gti_update_ioc_collection has its own requirements.txt with prettytable
pip install -r gti_update_ioc_collection/requirements.txt

# Each script is run directly, e.g.:
python corpus_search/gti_hunter.py -k YOUR_API_KEY -s 2025-01-01 -e 2025-01-31
python gti_search_last24h_malware/fetch_malware_l24h.py -k YOUR_API_KEY -l ransomware -t file -i
```

There are no tests, linting, or build steps configured.

## Code Patterns

- **API base URL**: All scripts use `https://www.virustotal.com/api/v3` with `x-apikey` header auth
- **Dependencies**: `requests` is universal; `tabulate` and `prettytable` used for display; `argparse` for CLI
- **Pagination**: Scripts handle VT cursor-based pagination in while loops, fetching up to 40 (or 300) items per page
- **Retry logic**: Most scripts implement exponential backoff with jitter for 429/5xx responses — patterns vary per script (not shared as a library)
- **Output**: Scripts typically print tables to stdout and save results as JSON or CSV files to an `output/` directory
- **Python version**: 3.10+ required (uses `X | None` union syntax in newer scripts)

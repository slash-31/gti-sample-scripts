# Reliaquest — VirusTotal Public Corpus File Removal Summary

## Background

Reliaquest submitted files to the VirusTotal (Google Threat Intelligence) public corpus using their API key between **September 1, 2025 and March 10, 2026**. They now need those files identified and removed from the public corpus.

Every file uploaded to VirusTotal is tagged with a unique submitter identifier tied to the API key that uploaded it. Reliaquest's submitter identifier is **`20f3cdee`**.

## Current Status with VirusTotal Support

- **Support Ticket:** #349077
- **Support Engineer:** Silvia Cuenca Ramos
- **Support's Request:** Reliaquest must provide a complete list of files they uploaded. Support will then verify each file was submitted by Reliaquest and that no other party also submitted the same file. Files where Reliaquest is the only submitter can be removed; files also submitted by others cannot, as the other submitter's upload independently justifies the file's presence in the corpus.

## The Challenge

The VirusTotal public corpus for US-based submissions contains **over 301 million files** for the timeframe in question. The platform does not offer a way to search or filter by a specific submitter identifier. This means:

- There is no search, report, or export that returns "all files uploaded by Reliaquest"
- The only way to check who submitted a specific file is to look up that file individually — one file at a time
- To find Reliaquest's files, every one of the 301M+ records would need to be downloaded and checked individually, which would exceed API usage limits and is not practically feasible

**In short, VirusTotal support is asking Reliaquest to provide a list that the platform's own tools do not allow them to generate.**

## What We Attempted

We built a custom tool (`gti_hunter.py`) designed to work within the API's constraints:

1. **Confirmed Reliaquest's submitter identifier** (`20f3cdee`) by submitting a test file and verifying the tag assigned to it
2. **Downloaded file listings** from the public corpus for the date range in smaller batches
3. **Checked each file individually** for Reliaquest's submitter identifier using concurrent lookups to speed up processing
4. **Exported matched results** to CSV with details including file hashes, file types, submission dates, and whether Reliaquest was the sole submitter

The tool works correctly and produces accurate results. However, it can only process a small fraction of the 301M+ file corpus before hitting API usage limits. In testing, we successfully processed ~3,780 files — a drop in the bucket relative to the full dataset.

## Why This Requires VirusTotal's Help

| What's Needed | Why the Customer Can't Do It |
|---|---|
| Search by submitter identifier | Not supported by the platform's search |
| Export all files for a specific submitter | No such report or export exists |
| Paginate through 301M+ files | Would require over 1 million API calls, exceeding usage limits |
| Check each file's submitter individually | One API call per file — not scalable to millions of records |

VirusTotal **does** track the submitter identifier internally for every file — it is stored and returned when looking up individual files. This means VirusTotal's backend systems have the data needed to run this query; it simply is not exposed to customers in a way that works at this scale.

## Recommended Next Step for Ticket #349077

We recommend responding to Silvia Cuenca Ramos with the following:

> We are unable to provide the requested file list because the VirusTotal API does not support searching by submitter identifier, and the US public corpus contains over 301 million files for our submission timeframe — far too many to enumerate through the API.
>
> We can confirm:
> - **Our submitter identifier:** `20f3cdee`
> - **Date range:** September 1, 2025 through March 10, 2026
> - **Request:** Remove all files where our identifier (`20f3cdee`) is the sole submitter
>
> Since VirusTotal tracks submitter identifiers internally for every file, we are requesting that your engineering team run a backend query to identify and process these files for removal. We have exhausted all available customer-facing options to produce this list ourselves.

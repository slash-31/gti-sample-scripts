# Reliaquest GTI Public Corpus Audit — Problem Statement & Work Summary

## The Problem

Reliaquest needs to identify and remove all files they uploaded to the VirusTotal/GTI **public corpus** using their API key during the period **September 1, 2025 through March 10, 2026**. Every file submitted to VirusTotal is stamped with a `source_key` — an 8-character hex hash derived from the API key used to upload it. Reliaquest's source_key is **`20f3cdee`**.

The core challenge: **the US public corpus contains over 301 million records** for this timeframe. There is no API-level way to filter those 301M records down to just the files submitted by a single source_key.

## The Support Ticket (Catch-22)

**VirusTotal Support Ticket:** #349077
**Support Engineer:** Silvia Cuenca Ramos

VirusTotal support has requested that Reliaquest **provide a list of all files they uploaded** so support can begin processing the removal request. Support needs to:

1. **Verify each file was submitted by Reliaquest** (source_key `20f3cdee`)
2. **Confirm Reliaquest was the sole submitter** (unique_sources == 1) — if other parties also submitted the same file, VT cannot remove it as the file's presence is justified by the other submitters

**This creates a catch-22:**
- Support needs the list to process the removal
- Reliaquest cannot produce the list because the API doesn't support searching by source_key
- The only way to build the list is to iterate through all 301M+ US submissions and check each one individually — which would exhaust Reliaquest's API quota many times over

## What the GTI API Does (and Doesn't) Support

- **`submitter:US`** — returns ALL US submissions (301M+), not a specific key
- **`submitter:me`** — resolves to group/country, not individual API key
- **`submitter:<source_key>`** — the API **does not support** filtering by source_key in search queries
- **`/files/{hash}/submissions`** — the only way to check which source_key submitted a given file, but requires querying each file individually (one API call per file, paginated at 40 results)

**There is no server-side mechanism to query "show me all files submitted by source_key `20f3cdee`."**

## What Was Built to Help

The `gti_hunter.py` tool was developed as a three-phase CLI to work within these API constraints:

**`discover`** — Identifies the source_key for any API key by submitting a probe file and reading back its submission metadata. This confirmed Reliaquest's key maps to `20f3cdee`.

**`fetch`** — Downloads candidate file listings from `/intelligence/search` using `submitter:<scope>` + date-range filters, saving to a local JSON cache. Returns up to 300 files per API call. Supports scoping by country code, source_key, user_id, or `me`.

**`audit`** — Reads the local cache and enriches each file with source_key attribution via `/files/{hash}/submissions`. Uses 10 concurrent threads, paginated lookups, and filtering by `--source-key 20f3cdee` or `--exclusive`. Exports matched results to CSV.

## Key Technical Iterations (12 commits)

| Evolution | Why |
|---|---|
| `submitter:me` didn't filter by key | Switched to resolving user_id, then to source_key verification per file |
| `unique_sources:1` rejected by API | Moved exclusive filtering to client-side |
| 4xx errors were being retried | Added early exit for non-retryable errors |
| Single-threaded was too slow | Added 10-thread concurrent submission lookups |
| Source_key not always on first page | Added paginated `/submissions` lookup to find target key |
| Single-pass hit API limits on large ranges | Split into fetch/audit two-phase workflow with local JSON caching |
| `submitter:me` resolved to country, not org | Made `--submitter` explicit, defaulting to `US` |

## Results Achieved (Scoped Queries)

Using `submitter:US` for the full date range (2025-09-01 to 2026-03-11):
- API reported **301M+ total hits** for US submissions
- **3,780 files** were fetched before pagination/quota constraints stopped progress
- Audit of those 3,780 produced attribution results in CSV
- **1,932 exclusive files** (unique_sources == 1) among the fetched set
- The tool works correctly — the problem is scale, not functionality

## The Fundamental Blocker

| Constraint | Impact |
|---|---|
| No server-side source_key filter | Cannot narrow 301M files to just `20f3cdee` |
| 300 results per API page | ~1,003,000+ API calls just to download the full file listing |
| Per-file attribution lookup | Each file needs an additional call to `/files/{hash}/submissions` |
| API quota limits | Total required calls (1M+ listing + N attribution) far exceed any practical budget |

## Recommendation for Support Ticket #349077

The list that Silvia Cuenca Ramos is requesting **cannot be produced by the customer through the public API** — this is a backend capability gap, not a customer tooling gap. The request should be escalated with the following context:

1. **Reliaquest's source_key is `20f3cdee`** — this is a verified, unique identifier for their API key that VT stamps on every submission
2. **The date range is 2025-09-01 through 2026-03-10**
3. **VT's own backend can query by source_key** — the `/files/{hash}/submissions` endpoint proves source_key is indexed per-file, so a backend database query filtering submissions by `source_key = '20f3cdee'` within the date range is feasible on VT's side
4. **The customer has no viable path to produce the list themselves** — the API would require 1M+ calls to paginate through the US corpus, exhausting quota and taking an impractical amount of time
5. **Reliaquest only needs files removed where they are the sole submitter** (unique_sources == 1) — VT can apply this filter server-side trivially

**Suggested ask to Silvia / VT Support:** Run a backend query for all submissions where `source_key = '20f3cdee'` between 2025-09-01 and 2026-03-10, filter to those where `unique_sources == 1`, and process those for removal. The customer is unable to produce this list through the API due to the 301M+ record corpus size and lack of source_key search support.

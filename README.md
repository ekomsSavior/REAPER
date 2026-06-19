# REAPER Core v2 – GitHub Secret Scanner

REAPER is a continuous, high‑performance scanner written in Go that hunts for exposed secrets across all public GitHub repositories. It scans code files, pull requests, issues, and commit messages for API keys, passwords, tokens, emails, database connection strings, security advisories (github related CVE), and other sensitive data.

## Features

- **Continuous operation** – Runs forever, sleeping between configurable cycles.
- **Advisory scanning** – Optionally checks repositories for known GitHub Security Advisories (CVEs).
- **Multi‑threaded** – Configurable worker pool (default 20) for concurrent scanning.
- **Comprehensive secret patterns** – AWS keys, GitHub tokens, Slack/Discord/Stripe keys, JWT, database URLs, private keys, emails, generic passwords and API keys (with entropy filtering).
- **Smart email filtering** – Automatically hides obfuscated emails (`user[at]example[dot]com`) and GitHub no‑reply addresses. Deduplicates emails per repository.
- **Rate‑limit aware** – Respects GitHub API limits; backs off when limits are hit.
- **Shared throttling** – Paces API calls and pauses every worker until GitHub's primary or secondary reset window has passed.
- **Stateful scanning** – Remembers already scanned repositories (`scanned_repos.txt`) to avoid re‑scanning.
- **Core v2 detector pipeline** – All sources share multi-line detection, masking, context, and deduplication.
- **Raw Git blob scanning** – Scans actual default-branch file content using recursive trees and raw blobs.
- **Custom detector packs** – Add software- or industry-specific JSON rule packs without recompiling.
- **Real‑time output** – Findings saved to both CSV and JSONL with masked values and redacted context.
- **Per-run output isolation** – Default runs receive timestamped folders so findings never accumulate into one giant file.
- **Single or batch mode** – Scan one repository, a list from a file, or continuously scan everything.
- **Keyword-focused discovery** – Narrow repository discovery with keywords, a wordlist, or an optional interactive prompt.
- **Graceful shutdown** – Saves state on Ctrl+C.

## Prerequisites

- **Go 1.21+** (only needed for building from source)
- **GitHub personal access token** (classic) with the `repo` and `public_repo` scopes.  
  Create one at: https://github.com/settings/tokens  
  For advisory scanning (`-scan-advisories=true`), also need `security_events` scope.

## Installation

Clone the repository and build the binary:

```bash
git clone https://github.com/ekomsSavior/REAPER.git
cd REAPER
go mod tidy
go build -o reaper .
```

## Usage

Set your GitHub token as an environment variable:

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

### Command‑line flags

| Flag | Default | Description |
|------|---------|-------------|
| `-workers` | 20 | Number of concurrent repository scanners |
| `-verbose` | false | Print each finding to the terminal |
| `-continuous` | true | Run forever, sleeping between cycles |
| `-sleep-minutes` | 60 | Minutes to sleep between continuous cycles |
| `-since-days` | 7 | Only scan repos updated in the last N days (0 = all) |
| `-scan-prs` | true | Scan pull request titles and bodies |
| `-scan-issues` | true | Scan issue titles and bodies |
| `-scan-commits` | true | Scan commit messages |
| `-scan-advisories` | false | Check each repository for GitHub Security Advisories |
| `-hide-obfuscated` | true | Hide obfuscated emails (e.g., user[at]example[dot]com) |
| `-entropy` | true | Enable entropy checking (reduces false positives for API keys) |
| `-min-stars` | 0 | Minimum number of stars a repository must have |
| `-output` | ./output | Base directory; when omitted, REAPER creates a timestamped run folder |
| `-repo` | "" | Single repository URL to scan (can be used multiple times) |
| `-repo-list` | "" | File containing repository URLs (one per line) |
| `-keyword` | "" | Repository search keyword; repeat it or use comma-separated values |
| `-wordlist` | "" | File containing repository search keywords, one per line |
| `-prompt-keywords` | false | Prompt for comma-separated keywords or an `@wordlist` path |
| `-rules` | "" | Load a custom JSON detector pack; repeat for multiple packs |
| `-rules-only` | false | Disable built-in detectors and use only custom packs |
| `-max-file-bytes` | 1048576 | Maximum Git blob size to scan |
| `-api-rps` | 1 | Maximum average GitHub API requests per second |
| `-api-burst` | 1 | Maximum burst of GitHub API requests |
| `-rate-limit-buffer` | 5s | Extra delay after GitHub's reported reset time |

### Modes of operation

#### 1. Continuous mode (scan all public repositories)

```bash
./reaper -workers=20 -verbose -continuous -sleep-minutes=5 -since-days=0
```

#### 2. Single repository scan

```bash
./reaper -repo https://github.com/owner/repo -verbose
```

#### 3. Multiple repositories (using multiple -repo flags)

```bash
./reaper -repo https://github.com/owner/repo1 -repo https://github.com/owner/repo2 -verbose
```

#### 4. Batch scan from a file

Create a file `repos.txt` with one URL per line:

```
https://github.com/owner/repo1
https://github.com/owner/repo2
```

Then run:

```bash
./reaper -repo-list repos.txt -verbose -scan-advisories=true
```

#### 5. Quiet mode (minimal output)

```bash
./reaper -workers=30 -sleep-minutes=5 -since-days=0
```

Only dots (.) are printed for progress; findings are still saved to files.

#### 6. Focus discovery with arbitrary search terms

Search terms narrow which repositories REAPER discovers; secret detection inside those repositories is unchanged. Terms can be anything the user chooses: a company, product, technology, event, organization, industry, project name, phrase, or other topic. REAPER has no fixed taxonomy or built-in topic restriction. Multiple terms use match-any behavior and repositories are deduplicated before scanning.

```bash
# One user-chosen topic or phrase
./reaper -keyword "renewable energy" -continuous=false

# Repeat the flag or provide comma-separated terms
./reaper -keyword kubernetes -keyword olympics -continuous=false
./reaper -keyword "kubernetes,olympics" -continuous=false

# One keyword or phrase per line; blank lines and # comments are ignored
./reaper -wordlist topics.txt -continuous=false

# Interactive entry: comma-separated keywords, @topics.txt, or blank for broad discovery
./reaper -prompt-keywords -continuous=false
```

Discovery terms and detector packs solve different halves of focused scanning:

- `-keyword` and `-wordlist` accept any user-chosen terms and select related repositories.
- `-rules` optionally defines additional credential formats to detect inside those repositories.

See [`examples/scopes.example.txt`](examples/scopes.example.txt) for a mixed arbitrary-term wordlist.

#### 7. Add software- or industry-specific detectors

Start from [`examples/rules.example.json`](examples/rules.example.json):

```json
{
  "rules": [
    {
      "name": "Example Vendor Token",
      "regex": "vendor_(?:live|prod)_[A-Za-z0-9]{24}",
      "severity": "critical",
      "entropy": true,
      "keywords": ["vendor", "client_secret", "api_key"]
    }
  ]
}
```

Use a pack alongside built-in detectors, or by itself:

```bash
./reaper -wordlist search-terms.txt -rules custom-rules.json -continuous=false
./reaper -keyword "your chosen topic" -rules custom-rules.json -rules-only -continuous=false
```

The first non-empty capture group is treated as the secret. Optional rule keywords are fast, case-insensitive content prefilters.

## Output Files

When `-output` is omitted, each invocation receives an isolated timestamped directory:

```text
output/
└── run_20260619_123456/
    ├── advisories.jsonl
    ├── reaper_findings.jsonl
    ├── reaper_findings_20260619_123456.csv
    └── scanned_repos.txt
```

If two runs begin during the same second, REAPER safely adds `_01`, `_02`, and so on. Passing `-output ./custom-path` uses that exact directory and preserves the previous append/persistence behavior.

- **`reaper_findings_TIMESTAMP.csv`** – CSV file with masked secret values (safe to share).
- **`reaper_findings.jsonl`** – Newline‑delimited JSON with masked secret values and redacted context.
- **`advisories.jsonl`** – Newline‑delimited JSON file containing security advisories (when `-scan-advisories=true`).
- **`scanned_repos.txt`** – List of already scanned repositories (full names). Prevents re‑scanning across cycles.

## Secret Patterns Detected

REAPER currently looks for the following patterns (non‑exhaustive list):

| Category | Examples |
|----------|----------|
| Cloud Keys | AWS Access Key (`AKIA...`), AWS Secret Key, Google API Key (`AIza...`) |
| Tokens | GitHub Token (`ghp_...`, `github_pat_...`), Slack Token (`xoxb-...`), Discord Bot Token, Stripe Live Secret Key (`sk_live_...`), JWT |
| Databases | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| Private Keys | RSA, SSH, EC private keys |
| Credentials | Email addresses, Generic passwords, Generic API keys |
| Other | Azure connection strings, Twilio, SendGrid, Heroku, OpenAI, Telegram, GitLab, Docker Hub, NPM, Pulumi, DigitalOcean, Alibaba Cloud |

## Email Filtering Logic

REAPER intelligently filters email addresses to reduce noise:

1. **Obfuscated emails** – Patterns like `user[at]example[dot]com`, `user AT example DOT com`, `user@[domain]` are excluded (unless `-hide-obfuscated=false`).
2. **GitHub no‑reply** – `noreply.github.com` and `users.noreply.github.com` addresses are excluded.
3. **Deduplication** – Each email appears only once per repository, even if found in multiple commits or files.

## Continuous Operation Details

When `-continuous=true` (the default), REAPER performs the following loop:

1. Searches GitHub for public repositories using the query `a is:public`, or one query per configured keyword (optionally filtered by `pushed:>date`).
2. For each new repository (not in `scanned_repos.txt`), it scans:
   - All files in the default branch.
   - Pull request titles and bodies.
   - Issue titles and bodies.
   - All commit messages.
   - Security advisories (if enabled).
3. Findings are written to CSV and JSONL in real time.
4. After the current search result pages are exhausted, REAPER sleeps for `-sleep-minutes`.
5. The cycle repeats, picking up newly created or updated repositories.

Press `Ctrl+C` at any time to stop gracefully; the list of scanned repositories is saved.

## Detailed jq Walkthrough: Analyzing REAPER Findings

The `reaper_findings.jsonl` file contains masked secrets in JSON format, one object per line. Set `RUN_DIR` to the run you want to inspect; this example selects the newest default run:

```bash
RUN_DIR=$(find ./output -maxdepth 1 -type d -name 'run_*' | sort | tail -1)
echo "$RUN_DIR"
```

Here is how to use `jq` to analyse that run.

### Basic viewing using jq

```bash
# View all findings (formatted)
jq '.' "$RUN_DIR/reaper_findings.jsonl"

# View raw lines (useful for counting)
cat "$RUN_DIR/reaper_findings.jsonl" | jq -c '.'
```

### Filtering by secret type

```bash
# AWS keys only
jq 'select(.SecretType == "AWS Access Key" or .SecretType == "AWS Secret Key")' "$RUN_DIR/reaper_findings.jsonl"

# Email addresses only
jq 'select(.SecretType == "Email Address")' "$RUN_DIR/reaper_findings.jsonl"

# GitHub tokens only
jq 'select(.SecretType == "GitHub Token")' "$RUN_DIR/reaper_findings.jsonl"

# JWT tokens only
jq 'select(.SecretType == "JWT Token")' "$RUN_DIR/reaper_findings.jsonl"
```

### Filtering by severity

```bash
# Critical severity only
jq 'select(.Severity == "CRITICAL")' "$RUN_DIR/reaper_findings.jsonl"

# High severity only
jq 'select(.Severity == "HIGH")' "$RUN_DIR/reaper_findings.jsonl"

# Critical or High
jq 'select(.Severity == "CRITICAL" or .Severity == "HIGH")' "$RUN_DIR/reaper_findings.jsonl"
```

### Filtering by repository

```bash
# Findings from a specific repository
jq 'select(.Repository == "owner/repo-name")' "$RUN_DIR/reaper_findings.jsonl"

# Findings from multiple repositories
jq 'select(.Repository | test("owner1|owner2"))' "$RUN_DIR/reaper_findings.jsonl"
```

### Filtering by file location

```bash
# Secrets found in actual code files (not issues/PRs/commits)
jq 'select(.FilePath != "issue" and .FilePath != "pull_request" and .FilePath != "commit_message")' "$RUN_DIR/reaper_findings.jsonl"

# Secrets found in environment files
jq 'select(.FilePath | endswith(".env"))' "$RUN_DIR/reaper_findings.jsonl"

# Secrets found in configuration files
jq 'select(.FilePath | test("\\.(yaml|yml|json|toml|ini)$"))' "$RUN_DIR/reaper_findings.jsonl"
```

### Statistics and counting

```bash
# Count findings by type
jq -r '.SecretType' "$RUN_DIR/reaper_findings.jsonl" | sort | uniq -c | sort -rn

# Count findings by severity
jq -r '.Severity' "$RUN_DIR/reaper_findings.jsonl" | sort | uniq -c | sort -rn

# Count findings per repository
jq -r '.Repository' "$RUN_DIR/reaper_findings.jsonl" | sort | uniq -c | sort -rn | head -20

# Total number of findings
jq -s 'length' "$RUN_DIR/reaper_findings.jsonl"
```

### Extracting specific fields

```bash
# Show only repository, file path, secret type, and secret value (tab-separated)
jq -r '[.Repository, .FilePath, .SecretType, .SecretValue] | @tsv' "$RUN_DIR/reaper_findings.jsonl"

# Show only critical findings with repository and URL
jq -r 'select(.Severity == "CRITICAL") | [.Repository, .SecretType, .URL] | @tsv' "$RUN_DIR/reaper_findings.jsonl"

# Export all masked findings to CSV
jq -r '[.Timestamp, .Repository, .FilePath, .LineNumber, .SecretType, .SecretValue, .URL, .Severity] | @csv' "$RUN_DIR/reaper_findings.jsonl" > all_secrets.csv
```

### Finding unique values

```bash
# List all unique email addresses found
jq -r 'select(.SecretType == "Email Address") | .SecretValue' "$RUN_DIR/reaper_findings.jsonl" | sort -u

# List all unique repositories that leaked secrets
jq -r '.Repository' "$RUN_DIR/reaper_findings.jsonl" | sort -u

# List all unique API keys (excluding emails)
jq -r 'select(.SecretType != "Email Address") | .SecretValue' "$RUN_DIR/reaper_findings.jsonl" | sort -u
```

### Time-based analysis

```bash
# Findings from the last hour (requires adjusting date format)
jq 'select(.Timestamp > "2026-04-14T12:00:00Z")' "$RUN_DIR/reaper_findings.jsonl"

# Show findings with timestamps
jq -r '[.Timestamp, .Repository, .SecretType] | @tsv' "$RUN_DIR/reaper_findings.jsonl"
```

### Analysing advisories (if enabled)

```bash
# View all advisories
jq '.' output/advisories.jsonl

# Critical severity advisories only
jq 'select(.Severity == "CRITICAL")' output/advisories.jsonl

# List all vulnerable repositories
jq -r '.Repository' output/advisories.jsonl | sort -u

# Count advisories by severity
jq -r '.Severity' output/advisories.jsonl | sort | uniq -c

# Find advisories for a specific repository
jq 'select(.Repository == "owner/repo-name")' output/advisories.jsonl
```

### Combining with grep for context

```bash
# Find secrets containing a specific keyword (e.g., "prod", "live")
jq -r 'select(.SecretValue | test("live|prod", "i")) | [.Repository, .SecretType, .SecretValue] | @tsv' "$RUN_DIR/reaper_findings.jsonl"

# Find secrets that look like they might be valid (long entropy)
jq 'select(.SecretType != "Email Address" and (.SecretValue | length > 20))' "$RUN_DIR/reaper_findings.jsonl"
```

### Real-time monitoring

```bash
# Watch new findings as they arrive (like tail -f)
tail -f "$RUN_DIR/reaper_findings.jsonl" | jq '.'

# Watch only critical findings in real time
tail -f "$RUN_DIR/reaper_findings.jsonl" | jq 'select(.Severity == "CRITICAL")'

# Watch only email findings (non-obfuscated)
tail -f "$RUN_DIR/reaper_findings.jsonl" | jq 'select(.SecretType == "Email Address")'
```

### Exporting for reports

```bash
# Generate a summary report
jq -s '
  "REAPER FINDINGS REPORT\n" +
  "=====================\n\n" +
  "Total findings: \(length)\n\n" +
  "By severity:\n" +
  (group_by(.Severity) | map("  \(.[0].Severity): \(length)") | join("\n")) +
  "\n\nBy type:\n" +
  (group_by(.SecretType) | map("  \(.[0].SecretType): \(length)") | join("\n"))
' "$RUN_DIR/reaper_findings.jsonl"

# Generate HTML report (simple)
jq -r '
  "<html><body><h1>REAPER Findings</h1><table border=1><tr><th>Timestamp</th><th>Repository</th><th>Type</th><th>Severity</th><th>File</th><th>URL</th></tr>" +
  (.[] | "<tr><td>\(.Timestamp)</td><td>\(.Repository)</td><td>\(.SecretType)</td><td>\(.Severity)</td><td>\(.FilePath)</td><td><a href=\"\(.URL)\">link</a></td></tr>") +
  "</table></body></html>"
' "$RUN_DIR/reaper_findings.jsonl" > report.html
```

## Troubleshooting

### "No new repositories found"

- Your GitHub token may be invalid or missing the required scopes.
- The search query `a is:public` may be rate‑limited. Wait a minute and try again.
- If you used `-since-days=0`, there are always repositories – check your network connection.

### High rate limit hits

- Reduce the number of workers (`-workers=10`).
- Increase `-sleep-minutes` (e.g., 30 or 60).
- Use a GitHub token with higher rate limits (authenticated requests allow 5,000 per hour).

### False positives (e.g., markdown links flagged as passwords)

The "Generic Password" pattern is intentionally broad. You can:
- Disable entropy checking for passwords (`-entropy=false`) or adjust the regex in `GetAllPatterns()`.
- Post‑filter the JSONL output using `jq`.

### Obfuscated emails appearing

By default, `-hide-obfuscated=true`. If you still see obfuscated emails, add more patterns to the `isObfuscatedEmail()` function in the source.

## Building and Testing Locally

1. Clone the repository.
2. Run `go mod tidy` to fetch dependencies.
3. Build with `go build -o reaper reaper.go`.
4. Test with a single repository:

   ```bash
   ./reaper -repo https://github.com/ekomsSavior/REAPER -verbose
   ```


## Disclaimer

REAPER is intended for **educational purposes and authorised security assessments** only. 

<img width="258" height="195" alt="reaper" src="https://github.com/user-attachments/assets/50554e14-efe2-4b63-8171-549cea81f098" />

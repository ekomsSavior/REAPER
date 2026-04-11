# REAPER – GitHub Secret Harvester

REAPER is a continuous, high‑performance scanner written in Go that hunts for exposed secrets across all public GitHub repositories. It scans code files, pull requests, issues, and commit messages for API keys, passwords, tokens, emails, database connection strings, and other sensitive data.

## Features

- **Continuous operation** – Runs forever, sleeping between configurable cycles.
- **Multi‑threaded** – Configurable worker pool (default 20) for concurrent scanning.
- **Comprehensive secret patterns** – AWS keys, GitHub tokens, Slack/Discord/Stripe keys, JWT, database URLs, private keys, emails, generic passwords and API keys (with entropy filtering).
- **Rate‑limit aware** – Respects GitHub API limits; backs off when limits are hit.
- **Stateful scanning** – Remembers already scanned repositories (`scanned_repos.txt`) to avoid re‑scanning.
- **Real‑time output** – Findings saved to both CSV (masked) and JSONL (unmasked) files.
- **Graceful shutdown** – Saves state on `Ctrl+C`.


The recommended way to use REAPER is via the single‑file `reaper.go` or the compiled `reaper` binary.

## Prerequisites

- **Go 1.21+** 
- **GitHub personal access token** (classic) with the `repo` and `public_repo` scopes.  
  Create one at: https://github.com/settings/tokens

## Installation

Clone the repository and build the binary:

```bash
git clone https://github.com/ekomsSavior/REAPER.git
cd REAPER
go mod tidy
go build -o reaper reaper.go
```

Alternatively, if you prefer the split files:

```bash
go build -o reaper ./cmd/reaper
```

## Usage

Set your GitHub token as an environment variable:

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

Run REAPER with the desired flags:

```bash
./reaper -workers=20 -verbose -continuous -sleep-minutes=5 -since-days=0
```

![IMG_3654(1)](https://github.com/user-attachments/assets/605713c3-ac91-46d9-9b73-9cc88e5397db)


### Command‑line flags

| Flag | Default | Description |
|------|---------|-------------|
| `-workers` | 20 | Number of concurrent repository scanners |
| `-verbose` | false | Print each finding to the terminal |
| `-continuous` | true | Run forever, sleeping between cycles |
| `-sleep-minutes` | 60 | Minutes to sleep between continuous cycles |
| `-since-days` | 7 | Only scan repos updated in the last N days (0 = all) |
| `-scan-prs` | true | Scan pull request titles, bodies, and comments |
| `-scan-issues` | true | Scan issue titles, bodies, and comments |
| `-scan-commits` | true | Scan commit messages |
| `-entropy` | true | Enable entropy checking (reduces false positives for API keys) |
| `-min-stars` | 0 | Minimum number of stars a repository must have |
| `-output` | ./output | Directory where output files are saved |

### Example: scan all public repositories (aggressive)

```bash
./reaper -workers=30 -sleep-minutes=5 -since-days=0 -verbose
```

### Example: scan only repositories updated in the last 7 days, less verbose

```bash
./reaper -since-days=7 -verbose=false
```

## Output Files

All findings are saved inside the `output/` directory (or a custom path set by `-output`).

- **`reaper_findings_TIMESTAMP.csv`** – CSV file with masked secret values (safe to share).
- **`reaper_findings.jsonl`** – Newline‑delimited JSON file containing **unmasked** secrets. Handle this file with extreme care.
- **`scanned_repos.txt`** – List of already scanned repositories (full names). Prevents re‑scanning across cycles.

## Secret Patterns Detected

REAPER currently looks for the following patterns (non‑exhaustive list):

- AWS Access Key (`AKIA...`)
- AWS Secret Key
- Google API Key (`AIza...`)
- GitHub Personal Access Token (`ghp_...`, `github_pat_...`)
- Slack Token (`xoxb-...`, `xoxp-...`, etc.)
- Discord Bot Token
- Stripe Live Secret Key (`sk_live_...`)
- JWT (JSON Web Tokens)
- Database connection strings: PostgreSQL, MySQL, MongoDB, Redis
- Private keys: RSA, SSH, EC
- Email addresses
- Generic passwords and API keys (with entropy validation)
- Azure connection strings
- Twilio, SendGrid, Heroku API keys

## Continuous Operation

When `-continuous=true` (the default), REAPER performs the following loop:

1. Searches GitHub for public repositories using the query `a is:public` (optionally filtered by `pushed:>date`).
2. For each new repository (not in `scanned_repos.txt`), it scans:
   - All files in the default branch.
   - All pull requests (titles, bodies, comments).
   - All issues (titles, bodies, comments).
   - All commit messages.
3. Findings are written to CSV and JSONL in real time.
4. After the current search result pages are exhausted, REAPER sleeps for `-sleep-minutes`.
5. The cycle repeats, picking up newly created or updated repositories.

Press `Ctrl+C` at any time to stop gracefully; the list of scanned repositories is saved.

## Building and Testing Locally

1. Clone the repository.
2. Run `go mod tidy` to fetch dependencies.
3. Build with `go build -o reaper reaper.go`.
4. Test with a small number of repositories:

   ```bash
   ./reaper -workers=5 -max-repos=50 -since-days=1 -verbose
   ```

   (Note: the `-max-repos` flag is not yet implemented in the current version; you can manually stop after a few seconds with `Ctrl+C`.)

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

## Disclaimer

REAPER is intended for **educational purposes and authorised security assessments** only


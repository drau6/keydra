# Keydra

Find what your vibe-coded app is leaking — before someone else does.

AI app builders (Lovable, Bolt, Cursor, v0, …) ship fast, and often ship with a
database wide open or a secret key inside the JavaScript bundle. `keydra`
looks at your **deployed** app the same way an outsider would, or at your
**source tree** before you deploy, and tells you what is exposed, with a
copy-paste fix.

> [!IMPORTANT]
> |**keydra is primarily designed to run as a standalone CLI tool. Running keydra as a publicly accessible service may expose sensitive data and introduce security risks. Use it with caution and implement appropriate security controls.**|

```
$ keydra scan https://my-app.example.com
                         █▄
   ▄▄                    ██ ▄
   ██ ▄█▀ ▄█▀█▄ ██ ██ ▄████ ████▄▄▀▀█▄
   ████   ██▄█▀ ██▄██ ██ ██ ██   ▄█▀██
  ▄██ ▀█▄▄▀█▄▄▄▄▄▀██▀▄█▀███▄█▀  ▄▀█▄██
                  ██                    v1.0.0
                ▀▀▀

Keydra — find what your vibe-coded app is leaking.
  keydra: only scan apps you own or have permission to test.

  url   https://my-app.example.com
  2 pages · 14 files scanned · 2.1s

  1  [Supabase] Supabase table "profiles" is publicly readable
     │ The table can be read with the public anon key. ...
     │ evidence  GET /rest/v1/profiles → 206, rows visible to anonymous role: 1204
     │ fix       alter table public.profiles enable row level security; …
```

## Quick start

**1. Install Go.** You need Go 1.27 or newer (`go version` to check; download from
https://go.dev/dl). With Go 1.21+ the right toolchain is fetched automatically
based on `go.mod`.

**2. Get the code and build it.**

```bash
unzip keydra.zip && cd keydra      # or: git clone <your repo> && cd keydra
go build -o bin/keydra ./cmd/keydra   # or: make build
```

Windows (PowerShell): `go build -o bin\keydra.exe ./cmd/keydra`

You do not need to rename the module to build locally. Replace
`github.com/drau6/keydra` with your own path only when you publish the repo
(or if you want `go install github.com/<you>/keydra/cmd/keydra@latest` to work).

**3. Run your first scan.**

```bash
# source code, before you deploy: safe, no network
./bin/keydra scan --repo .

# a deployed app you own (or have written permission to test)
./bin/keydra scan https://my-app.example.com

# also follow internal links, because secrets often hide on /admin or /dashboard
./bin/keydra scan https://my-app.example.com --depth 2

# see every check Keydra performs
./bin/keydra rules
```

**4. Optional: install it on your PATH.**

```bash
go install ./cmd/keydra      # installs to $(go env GOPATH)/bin
keydra version
```

**5. Optional: run the tests.** `go test ./...` (or `make test`).

Notes: colors turn on automatically in a terminal. On legacy Windows `cmd.exe`
you may see raw escape codes; use Windows Terminal/PowerShell or `--no-color`.
The large banner is skipped when output is piped, when the terminal is narrower
than the banner (`COLUMNS`), or with `--no-banner`.

## Install

```
go install github.com/drau6/keydra/cmd/keydra@latest
```

(after you have replaced `yourname` and pushed the repo), or `make build` and use
`bin/keydra`.

## Usage

```
keydra scan <url> [flags]          # scan a deployed app
keydra scan --repo <dir> [flags]   # scan source before you deploy
keydra scan --list <file> [flags]  # scan every URL in the file, one per line (max 50)
keydra rules                       # list every check
keydra <url>                       # shortcut for scan

  --repo <dir>      scan a local source tree instead of a URL (no network)
  --list <file>     scan a list of URLs, one per line (# comments and blank lines ignored, max 50)
  --format <fmt>    text | json | sarif (default text); --json is a shortcut
  --no-banner       one-line title instead of the ASCII-art banner
  --color <mode>    auto|always|never (honors NO_COLOR and FORCE_COLOR; --no-color also works)
  --no-probe        static analysis only, never contact discovered backends
  --validate        opt-in: ask each provider (one read-only request) whether a detected secret is still active
  --fail-on <sev>   exit 1 at/above severity: info|low|medium|high|critical|never (default high)
  --depth N         page levels to crawl in URL mode: 1 = only the given page (default),
                    2 = also its internal links, up to 5
  --max-pages N     maximum HTML pages to fetch in URL mode (default 20, max 200)
  --sitemap         also scan pages listed in /sitemap.xml
  --max-files N     JS files to download in URL mode (default 40)
  --third-party     also scan scripts hosted on other origins
  --timeout 15s     per-request timeout
  -v                show full fix snippets
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` error. With
`--list`, `2` also means "at least one target failed to scan" (unless findings
already forced exit 1).

### What the output looks like

A repo scan of a small vibe-coded app (`--no-color --no-banner`; on an
interactive terminal the banner is ASCII art and the `│` gutter is colored by
severity — red critical, orange high, blue low):

```
  KEYDRA  v1.0.0
  keydra: only scan apps you own or have permission to test.

  repo  my-app
  3 files scanned · 1ms

  1  [Supabase] Supabase service/secret key exposed in client code
     │ This key bypasses Row Level Security. Whoever holds it has full read/write access to the whole database.
     │ evidence eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWowMTIzNDU2Nzg5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0OTgxODI0OSwiZXhwIjoyMDY1Mzk0MjQ5fQ.AAAAAAAAbbbbbbbbCCCCCCCCddddddddEEEEEEEE
     │ fix      Rotate the key in Supabase → Project Settings → API now, remove it from the frontend and use it only from server-side code.

  2  [Repository] .env is not covered by .gitignore
     │ Environment files normally hold server secrets. If this file is committed, every secret in it is in your git history.
     │ where    .env
     │ fix      Add ".env*" and "!.env.example" to .gitignore. If it was already committed: `git rm --cached .env`, then rotate every key inside and purge history.

  3  [Secrets] Possible unnamed secret (high-entropy string) exposed in client code
     │ This value ships to every visitor's browser and can be copied by anyone.
     │ evidence eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWowMTIzNDU2Nzg5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0OTgxODI0OSwiZXhwIjoyMDY1Mzk0MjQ5fQ.AAAAAAAAbbbbbbbbCCCCCCCCddddddddEEEEEEEE
     │ where    lib/api.js
     │ fix      Keydra found a long, random-looking string that matches no known key format. Check whether it is a credential: if so, rotate it and move it server-side. Build artifacts such as hashes or encoded assets can be ignored.

  note: Supabase configuration found in source; run `keydra scan <deployed-url>` to test the live backend
```

Every finding shows the matched value in full (evidence), where it was found,
and a copy-paste fix — so a scan report is all you need to start remediation.
Values above are examples, not real keys.

## Crawling more than one page

By default only the page you give is scanned (plus its scripts, lazy chunks and
source maps). Use `--depth` to follow internal links, and `--sitemap` to add the
pages a site lists in `/sitemap.xml`:

```
keydra scan https://my-app.example.com --depth 3 --max-pages 40
keydra scan https://my-app.example.com --sitemap
```

* Crawling stays on the same host, is breadth-first, capped by `--max-pages` and
  paced with a short pause between pages.
* Only `GET` requests are sent. Links that look like actions (`logout`,
  `sign-out`, `delete`, `remove`, `unsubscribe`, `cancel`, …) and static assets
  are never followed.
* `--depth` follows links found in the HTML. Client-rendered apps (a bare
  `<div id="root">`) have almost none; their routes live in the JavaScript
  bundles, which Keydra already reads. If `--depth` finds no links you get a
  note, and `--sitemap` is the next thing to try. Server-rendered sites (Next.js
  SSR, Astro, Rails, PHP) benefit the most.

## Bulk testing a list of URLs

Put your targets in a plain text file, one URL per line:

```
# staging and production for my-app
https://staging.my-app.example.com
https://www.my-app.example.com
https://admin.my-app.example.com
```

Blank lines and `#` comment lines are ignored. Then scan them all in one go:

```
keydra scan --list urls.txt                       # text report, one section per target
keydra scan --list urls.txt --format json > report.json
keydra scan --list urls.txt --format sarif > report.sarif
keydra scan --list urls.txt --validate            # also live-check the secrets it finds
```

How bulk mode works:

* Targets are scanned **sequentially**, one after another, so a list never
  floods a host or the network. Every `scan` flag (`--depth`, `--sitemap`,
  `--validate`, `--fail-on`, …) applies to each target.
* **Text output** prints one full report per target, separated by a rule line,
  and ends with a one-line tally:
  `2 of 3 targets scanned · 1 clean · 1 with findings · 1 failed (see stderr)`.
* **JSON** is a single array with one element per scanned target; **SARIF** is
  one log with one run per target (GitHub code scanning accepts multi-run
  files).
* A target that fails to scan (DNS failure, refused connection, timeout) is
  reported on `stderr` and the remaining targets continue.
* **Exit codes** work over all targets combined: `1` if any finding meets
  `--fail-on` anywhere, `2` only if *no* target could be scanned — or, when
  some but not all failed, `2` after the findings check. `0` means every
  target was scanned and clean.

The list is capped at 50 URLs per run. This tool is for auditing your own
estate — it is not a mass-scanning utility.

## Repo mode (before you deploy)

```
keydra scan --repo .
```

Static checks on your source tree, no network at all:

* `.env` files not covered by `.gitignore` (ignored `.env` files are skipped, not flagged)
* secrets behind browser-exposed prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`)
* Supabase SQL migrations: tables created without RLS, RLS explicitly disabled, `using (true)` policies open to anon/public
* Firebase rules: `if true`, `.read/.write: true`, time-limited test-mode rules
* Convex functions that never check the caller's identity (heuristic)
* every secret detector from URL mode, run over all source and build output

Limits: only the root `.gitignore` is read, SQL is parsed with regexes (ORM-only
schemas such as Prisma/Drizzle are not understood), and the Convex check is a
heuristic. Treat findings as leads to verify.

## CI and GitHub code scanning

`--format sarif` writes SARIF 2.1.0, which GitHub shows as code-scanning alerts.
The banner and notes go to stderr, so stdout is clean:

```yaml
# .github/workflows/keydra.yml  (pin actions to their current major versions)
name: keydra
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: stable }
      - run: go install github.com/drau6/keydra/cmd/keydra@latest
      - run: keydra scan --repo . --format sarif --fail-on never > keydra.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: keydra.sarif }
```

SARIF is most useful with `--repo`, where findings point at real files. Keydra
does not track line numbers yet, so every alert is anchored to line 1 of its file.
To fail a pipeline on a deployed staging app instead:

```
keydra scan https://staging.my-app.com --fail-on high
```

## Detector reference

Generated from the code by `scripts/sync-readme.sh` (`make docs`); a test fails if
this list drifts from the real checks. `keydra rules` prints the same list.

<!-- detectors:start -->

**Secrets · Payments**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `stripe-secret-key` | critical | Stripe live secret key | URL + repo |
| `stripe-restricted-key` | high | Stripe restricted key | URL + repo |
| `midtrans-server-key` | critical | Midtrans server key | URL + repo |
| `xendit-secret-key` | critical | Xendit secret key | URL + repo |
| `square-token` | critical | Square access token | URL + repo |
| `razorpay-key` | critical | Razorpay live key | URL + repo |

**Secrets · AI providers**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `openai-key` | critical | OpenAI API key | URL + repo |
| `anthropic-key` | critical | Anthropic API key | URL + repo |
| `groq-key` | high | Groq API key | URL + repo |
| `perplexity-key` | high | Perplexity API key | URL + repo |
| `huggingface-token` | medium | Hugging Face token | URL + repo |

**Secrets · Cloud & source control**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `github-token` | critical | GitHub token | URL + repo |
| `github-pat` | critical | GitHub fine-grained personal access token | URL + repo |
| `gitlab-token` | high | GitLab personal access token | URL + repo |
| `npm-token` | high | npm access token | URL + repo |
| `digitalocean-token` | high | DigitalOcean API token | URL + repo |
| `aws-access-key` | high | AWS access key ID | URL + repo |
| `aws-secret-access-key` | critical | AWS secret access key | URL + repo |
| `google-api-key` | low | Google API key | URL + repo |

**Secrets · Messaging & email**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `slack-token` | high | Slack token | URL + repo |
| `sendgrid-key` | high | SendGrid API key | URL + repo |
| `mailgun-key` | high | Mailgun API key | URL + repo |
| `resend-key` | high | Resend API key | URL + repo |
| `telegram-bot-token` | high | Telegram bot token | URL + repo |
| `discord-webhook` | medium | Discord webhook URL | URL + repo |
| `discord-bot-token` | high | Discord bot token | URL + repo |

**Secrets · Databases**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `neon-connection-string` | critical | Neon Postgres connection string | URL + repo |
| `upstash-redis-url` | critical | Upstash Redis connection URL | URL + repo |
| `upstash-rest-token` | high | Upstash REST token | URL + repo |
| `turso-auth-token` | critical | Turso database auth token | URL + repo |
| `database-url-with-password` | critical | Database connection string with password | URL + repo |

**Secrets · Auth**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `clerk-secret-key-live` | critical | Clerk live secret key | URL + repo |
| `clerk-secret-key-test` | high | Clerk development secret key | URL + repo |
| `auth0-client-secret` | high | Auth0 client secret | URL + repo |

**Secrets · Backend platforms**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `appwrite-api-key` | critical | Appwrite server API key | URL + repo |
| `appwrite-set-key` | high | Appwrite server key hardcoded via setKey() | URL + repo |
| `convex-deploy-key` | critical | Convex deploy key | URL + repo |
| `shopify-token` | high | Shopify access token | URL + repo |
| `notion-token` | high | Notion integration token | URL + repo |

**Secrets · Other**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `private-key` | critical | Private key block | URL + repo |
| `high-entropy-string` | low | Possible unnamed secret (high-entropy string) | URL + repo |

**Supabase**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `supabase-service-key-exposed` | critical | Supabase service_role / secret key shipped to the browser | URL + repo |
| `supabase-table-exposed` | high/critical | Table readable with the public anon key (missing or weak RLS) | URL |
| `supabase-rls-missing` | high/critical | Table created in SQL migrations without Row Level Security | Repo |
| `supabase-rls-disabled` | high | Row Level Security explicitly disabled | Repo |
| `supabase-policy-open` | medium/high | Policy with using (true) open to anon/public | Repo |

**Firebase**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `firebase-rtdb-open` | high/critical | Realtime Database readable without login | URL |
| `firebase-firestore-open` | high/critical | Firestore collection readable without login | URL |
| `firebase-storage-listable` | high | Storage bucket listable without login | URL |
| `firebase-rules-open` | high/critical | Rules with `if true` or .read/.write: true | Repo |
| `firebase-rules-test-mode` | high | Time-limited test-mode rules still in place | Repo |

**Appwrite**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `appwrite-collection-exposed` | high/critical | Collection readable with the "Any" role (Databases API) | URL |
| `appwrite-table-exposed` | high/critical | Table readable with the "Any" role (TablesDB API) | URL |
| `appwrite-bucket-exposed` | high | Storage bucket listable without login | URL |

**PocketBase**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `pocketbase-collection-exposed` | high/critical | Collection with an empty (public) List rule | URL |
| `pocketbase-admin-ui-public` | low | Admin dashboard reachable from the internet | URL |

**Convex**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `convex-public-query-returns-data` | medium | Query returns data to unauthenticated callers | URL |
| `convex-public-functions-no-auth` | medium | Public functions that never check the caller's identity (heuristic) | Repo |

**Repository**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `env-file-not-ignored` | high | .env file not covered by .gitignore | Repo |
| `secret-in-public-env` | high | Secret stored in a NEXT_PUBLIC_ / VITE_ / REACT_APP_ / EXPO_PUBLIC_ variable | Repo |

**Exposure**

| ID | Severity | Detects | Where |
|---|---|---|---|
| `source-map-exposed` | low | Public JavaScript source map | URL |

<!-- detectors:end -->

## Safety and ethics

* **Only scan apps you own or have written permission to test.**
* Checks are passive and read-only: plain `GET` requests (plus a `POST` to
  Convex's query-only endpoint), throttled and capped per backend. Nothing is
  written, deleted or modified.
* `--validate` is opt-in and off by default. When enabled, each detected secret
  is sent once to its own provider's read-only endpoint (for example
  `api.github.com/user`) to confirm whether the credential is still active,
  rejected or unverifiable. That request goes to the provider, never to the
  target, and only the verdict is shown in the report.
* Response bodies are not stored. Only status codes, row counts and top-level
  key names are used as evidence.
* Secrets are shown in full in reports. Treat scan output as sensitive: it
  contains live credentials, so don't paste it into issues, chats or logs
  others can read.
* There is no parallel or unbounded mass-scan mode: list scanning (`--list`) is
  sequential and capped at 50 URLs per run.

## Project layout

```
cmd/keydra/        entry point (thin main)
internal/cli/        commands, flags, exit codes
internal/scanner/    orchestrates fetch → extract → detect → probe (URL and repo mode)
internal/fetcher/    downloads page, scripts, lazy chunks, source maps
internal/extractor/  pulls backend config (Supabase, Firebase, Appwrite, PocketBase, Convex) out of JS
internal/detectors/  secret rules (with validators) and the check catalog
internal/probe/      read-only backend checks
internal/repo/       --repo mode: file walker, .gitignore, source-level checks
internal/report/     terminal, JSON and SARIF output
internal/model/      shared types
internal/buildinfo/  version injected via ldflags
scripts/             README generator
```

## Adding a detector

1. Append a rule in `internal/detectors/rules.go` (use `.validated(...)` to reject
   placeholders or look-alikes from other services).
2. Add a case to `TestServiceSpecificDetectors` in `rules_test.go`. Build
   secret-shaped test strings at runtime so the repo never trips secret scanners.
3. Run `make docs` to refresh the table above.

Checks that are not regex rules (probes, repo checks) are listed in
`internal/detectors/catalog.go`.

## Known limitations

* Detection depends on config being readable in the JavaScript bundle. Heavily
  obfuscated or server-rendered apps may not expose it.
* `--depth` only discovers pages through HTML `<a href>` links and one level of
  `sitemap.xml`; it does not execute JavaScript or log in, so pages behind
  authentication are not reachable.
* Convex function names are often not recoverable from modern bundles
  (`api.module.fn` property chains), so URL mode only probes the string-style
  references it can find. Use `--repo` for Convex projects.
* Appwrite's Databases API (collections) and TablesDB API (tables) are both
  checked; the response shapes follow the public docs and have been tested
  against mock servers only.
* An empty table or one fully hidden by RLS looks identical from outside, so
  those are never reported.
* Database URLs in client code are flagged as Critical unless they look like
  placeholders or local development hosts.

## Roadmap

* Supabase RPC functions and storage bucket exposure
* Line numbers in findings (and in SARIF)
* Authenticated scanning (cookie/header) for pages behind a login
* Nested sitemap indexes
* More detectors: Cloudflare, Vercel, Railway, PlanetScale, Resend domains

# Changelog

All notable changes to Keydra are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com); versions
follow [Semantic Versioning](https://semver.org).

## [Unreleased]

## [1.1.0] — 2026-11-18

### Added

- `--redact` masks credential values in text and JSON reports. SARIF always
  masks credential evidence because SARIF logs are commonly uploaded to
  third-party services.
- `--allow-private` lets a scan of a public target reach a local development
  backend. Scans whose target is already local allow it automatically.
- Version reporting now falls back to the module version recorded by
  `go install ...@latest` when no `-ldflags` version was injected.

### Fixed

- Restored the permission notice under the banner and made the ASCII-art
  banner show the actual version instead of a hard-coded one.
- Redirects can no longer leave the scanned site or reach private/internal
  addresses, and backend endpoints discovered in target-controlled code are
  skipped unless they are public or explicitly allowed.
- Backend probes now validate every redirect hop and refuse hostnames that
  resolve to loopback, private or link-local addresses, not just literal
  private IPs.
- `--third-party` still relaxes the same-site rule but no longer fetches
  scripts, chunks or source maps from private/local addresses.
- Repo mode now honors `--max-files` when it is set, and non-positive
  `--timeout`/`--max-files` values are rejected instead of silently changing
  validation behavior.
- `.env.example`/`.env.sample` files, documentation references and empty or
  placeholder values no longer trigger `secret-in-public-env`.
- JSON output now round-trips back into the report types.

## [1.0.0] — 2026-11-12

First release. Keydra finds what a vibe-coded app is leaking — from the
deployed site the way an outsider sees it, or from the source tree before
you deploy — with a copy-paste fix for every finding.

### Added

- **URL mode**: fetch a deployed app's pages, scripts, lazy chunks and source
  maps, and scan them like an outsider would.
- **Repo mode** (`--repo`): static checks on local source with no network —
  `.env` files not covered by `.gitignore`, secrets behind browser-exposed
  env prefixes (`NEXT_PUBLIC_`, `VITE_`, …), Supabase SQL migrations without
  RLS, Firebase rules, Convex functions without identity checks.
- **39 checks** in the catalog: secret detectors (Stripe, OpenAI, Anthropic,
  AWS, GitHub, GitLab, npm, Slack, SendGrid, Mailgun, Resend, Telegram,
  Discord, database URLs, Clerk, Auth0, Appwrite, Shopify, Square, Razorpay,
  Notion, Groq, Perplexity, Hugging Face, private keys, …) plus live backend
  probes for Supabase, Firebase, Appwrite, PocketBase and Convex.
- **Generic high-entropy detection**: long random-looking strings that match
  no known key format, reported as low-severity leads (capped at 10 per scan).
- **Live key validation** (`--validate`, opt-in): one read-only request per
  provider to report a detected secret as active, rejected or unverified.
- **Bulk mode** (`--list`): scan up to 50 URLs from a text file, sequentially,
  with per-target reports, a final tally and combined exit codes.
- **Crawling** (`--depth`, `--sitemap`, `--max-pages`): follow internal links
  and sitemap entries on the same host.
- **Output formats**: text (ANSI, banner), JSON (single
  object or array), and SARIF 2.1.0 (multi-run) for GitHub code scanning.
- **Exit codes for CI**: `0` clean, `1` findings at/above `--fail-on`, `2`
  error; reports show secret evidence in full, so treat scan output as
  sensitive.
- **Safety posture**: read-only checks, same-host crawling, no parallel or
  unbounded mass scanning, permission reminder printed under the banner.

### Known limitations

- Detection depends on config being readable in client-side JavaScript;
  obfuscated or server-rendered apps may hide it.
- `--depth` does not execute JavaScript or log in; pages behind
  authentication are not reachable.
- Only the root `.gitignore` is read; SQL is parsed with regexes.
- Provider validation endpoints follow public docs and may need adjustment
  if a provider changes its API (such results surface as "unverified").

[Unreleased]: https://github.com/drau6/keydra/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/drau6/keydra/releases/tag/v1.1.0
[1.0.0]: https://github.com/drau6/keydra/releases/tag/v1.0.0

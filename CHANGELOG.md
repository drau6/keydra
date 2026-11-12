# Changelog

All notable changes to Keydra are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com); versions
follow [Semantic Versioning](https://semver.org).

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

[1.0.0]: https://github.com/drau6/keydra/releases/tag/v1.0.0

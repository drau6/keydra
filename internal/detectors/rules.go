// Package detectors contains pattern rules for secrets that must never ship
// inside client-side code, plus a catalog of every check Keydra performs.
package detectors

import (
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/drau6/keydra/internal/model"
)

// Rule describes one secret pattern.
type Rule struct {
	ID       string
	Name     string
	Group    string // used to organize the catalog and README
	Severity model.Severity
	Pattern  *regexp.Regexp
	Fix      string
	// Validate optionally rejects regex matches that are not real secrets
	// (placeholders, look-alikes from other services).
	Validate func(match string) bool
}

// Match is one occurrence of a rule in some text.
type Match struct {
	Rule  Rule
	Value string
}

const rotate = "Revoke and rotate this key now, then move the call to a server-side function or API route and read the key from an environment variable."
const rotateDB = "Rotate the database password now and remove the connection string from client code. Browsers must never talk to the database directly; go through a server-side API."

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

func r(id, name, group string, sev model.Severity, p, fix string) Rule {
	return Rule{ID: id, Name: name, Group: group, Severity: sev, Pattern: re(p), Fix: fix}
}

func (x Rule) validated(f func(string) bool) Rule { x.Validate = f; return x }

// Group names, in the order they appear in the catalog.
const (
	gPayments = "Payments"
	gAI       = "AI providers"
	gCloud    = "Cloud & source control"
	gMessages = "Messaging & email"
	gDB       = "Databases"
	gAuth     = "Auth"
	gBackend  = "Backend platforms"
	gOther    = "Other"
)

var groupOrder = []string{gPayments, gAI, gCloud, gMessages, gDB, gAuth, gBackend, gOther}

// Stripe live secret keys are "sk_live_51…" (long) or, for legacy accounts,
// exactly 24 characters. This keeps Clerk's sk_live_ keys from matching.
func isStripeLive(v string) bool {
	return strings.HasPrefix(v, "sk_live_51") || len(v) == len("sk_live_")+24
}

func notStripe(v string) bool {
	return !strings.HasPrefix(v, "sk_live_51") && !strings.HasPrefix(v, "sk_test_51")
}

// distinctChars counts unique runes in s.
func distinctChars(s string) int {
	set := map[rune]bool{}
	for _, r := range s {
		set[r] = true
	}
	return len(set)
}

// placeholderWords marks values that are clearly human-written filler.
var placeholderWords = []string{
	"your", "placeholder", "example", "apikey", "api_key", "process.env",
	"import.meta.env", "{{", "}}", "<", ">", "todo", "insert", "dummy", "fake", "xxx",
}

// looksRandom rejects values that are not plausibly secrets: too few distinct
// characters (repeated filler) or containing placeholder wording.
func looksRandom(v string, minDistinct int) bool {
	if distinctChars(v) < minDistinct {
		return false
	}
	low := strings.ToLower(v)
	for _, p := range placeholderWords {
		if strings.Contains(low, p) {
			return false
		}
	}
	return true
}

// openAIKey accepts the prefixed project/service-account forms as-is and
// applies a randomness check to the legacy 48-character form, which is short
// enough to collide with other "sk-" tokens.
func openAIKey(v string) bool {
	if strings.HasPrefix(v, "sk-proj-") || strings.HasPrefix(v, "sk-svcacct-") {
		return true
	}
	return looksRandom(v, 16)
}

// resendKey guards the short "re_" prefix against random identifiers.
func resendKey(v string) bool { return looksRandom(v, 12) }

// quotedValue extracts the text between the first and last quote of a
// name-anchored match such as VAR="…" or .setKey("…").
func quotedValue(match string) string {
	i := strings.IndexAny(match, "\"'")
	j := strings.LastIndexAny(match, "\"'")
	if i < 0 || j <= i {
		return ""
	}
	return match[i+1 : j]
}

// randomQuoted validates name-anchored rules whose secret is a quoted value.
func randomQuoted(minDistinct int) func(string) bool {
	return func(match string) bool { return looksRandom(quotedValue(match), minDistinct) }
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// awsSecretKey rejects 40-character hex strings (SHA-1 digests are common in
// code) and low-diversity filler.
func awsSecretKey(match string) bool {
	v := strings.TrimRight(match, "\"'")
	if len(v) < 40 {
		return false
	}
	token := v[len(v)-40:]
	return !isHex(token) && looksRandom(token, 16)
}

var placeholderPasswords = map[string]bool{
	"password": true, "pass": true, "changeme": true, "secret": true, "yourpassword": true,
	"your_password": true, "postgres": true, "root": true, "admin": true, "123456": true, "example": true,
}

var specialHosts = []string{"neon.tech", "upstash.io"}

// realDBURL rejects documentation placeholders and local development URLs,
// and URLs handled by a more specific rule.
func realDBURL(v string) bool {
	i := strings.Index(v, "://")
	if i < 0 {
		return false
	}
	rest := v[i+3:]
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return false
	}
	cred, host := rest[:at], strings.ToLower(rest[at+1:])
	colon := strings.Index(cred, ":")
	if colon < 0 {
		return false
	}
	pass, _ := url.PathUnescape(cred[colon+1:])
	if placeholderPasswords[strings.ToLower(pass)] || strings.ContainsAny(pass, "*<>${}") {
		return false
	}
	for _, h := range []string{"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "example"} {
		if strings.Contains(host, h) {
			return false
		}
	}
	for _, h := range specialHosts {
		if strings.HasSuffix(host, h) || strings.Contains(host, "."+h) {
			return false
		}
	}
	return true
}

var rules = []Rule{
	// Payments
	r("stripe-secret-key", "Stripe live secret key", gPayments, model.Critical, `\bsk_live_[0-9A-Za-z]{24,}\b`, rotate).validated(isStripeLive),
	r("stripe-restricted-key", "Stripe restricted key", gPayments, model.High, `\brk_live_[0-9A-Za-z]{24,}\b`, rotate),
	r("midtrans-server-key", "Midtrans server key", gPayments, model.Critical, `\b(?:SB-)?Mid-server-[A-Za-z0-9_\-]{20,}`, rotate),
	r("xendit-secret-key", "Xendit secret key", gPayments, model.Critical, `\bxnd_(?:development|production)_[A-Za-z0-9]{40,}`, rotate),
	r("square-token", "Square access token", gPayments, model.Critical, `\bsq0atp-[0-9A-Za-z_\-]{22}\b`, rotate),
	r("razorpay-key", "Razorpay live key", gPayments, model.Critical, `\brzp_live_[A-Za-z0-9]{14,}\b`, rotate),

	// AI providers
	r("openai-key", "OpenAI API key", gAI, model.Critical, `\bsk-(?:proj-|svcacct-)[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{48}\b`, rotate).validated(openAIKey),
	r("anthropic-key", "Anthropic API key", gAI, model.Critical, `\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,}`, rotate),
	r("groq-key", "Groq API key", gAI, model.High, `\bgsk_[A-Za-z0-9]{20,}\b`, rotate),
	r("perplexity-key", "Perplexity API key", gAI, model.High, `\bpplx-[A-Za-z0-9]{30,}\b`, rotate),
	r("huggingface-token", "Hugging Face token", gAI, model.Medium, `\bhf_[A-Za-z0-9]{34,}\b`,
		"Revoke this token at huggingface.co → Settings → Access Tokens. Anyone holding it can read your private models and datasets (and write, if it has write scope)."),

	// Cloud & source control
	r("github-token", "GitHub token", gCloud, model.Critical, `\bgh[pousr]_[A-Za-z0-9]{36,}\b`, rotate),
	r("github-pat", "GitHub fine-grained personal access token", gCloud, model.Critical, `\bgithub_pat_[A-Za-z0-9_]{20,}\b`, rotate),
	r("gitlab-token", "GitLab personal access token", gCloud, model.High, `\bglpat-[A-Za-z0-9_\-]{20,}\b`, rotate),
	r("npm-token", "npm access token", gCloud, model.High, `\bnpm_[A-Za-z0-9]{36}\b`,
		"Revoke this token at npmjs.com → Access Tokens and republish any affected packages with 2FA enabled. A leaked publish token lets anyone push malware to your packages."),
	r("digitalocean-token", "DigitalOcean API token", gCloud, model.High, `\bdop_v1_[a-f0-9]{64}\b`, rotate),
	r("aws-access-key", "AWS access key ID", gCloud, model.High, `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, rotate),
	r("aws-secret-access-key", "AWS secret access key", gCloud, model.Critical,
		`(?i)aws[_a-z\-]*secret[_a-z\-]*\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}\b`, rotate).validated(awsSecretKey),
	r("google-api-key", "Google API key", gCloud, model.Low, `\bAIza[0-9A-Za-z_\-]{35}\b`,
		"Firebase web keys are meant to be public, but the same key shape also works for billable APIs (e.g. Gemini). Restrict it by HTTP referrer and by API in Google Cloud Console."),

	// Messaging & email
	r("slack-token", "Slack token", gMessages, model.High, `\bxox[baprs]-[A-Za-z0-9\-]{10,}`, rotate),
	r("sendgrid-key", "SendGrid API key", gMessages, model.High, `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`, rotate),
	r("mailgun-key", "Mailgun API key", gMessages, model.High, `\bkey-[a-f0-9]{32}\b`, rotate),
	r("resend-key", "Resend API key", gMessages, model.High, `\bre_[A-Za-z0-9_]{32,}\b`, rotate).validated(resendKey),
	r("telegram-bot-token", "Telegram bot token", gMessages, model.High, `\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b`, rotate),
	r("discord-webhook", "Discord webhook URL", gMessages, model.Medium, `https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+`,
		"Delete the webhook and recreate it; anyone with the URL can post to your channel."),
	r("discord-bot-token", "Discord bot token", gMessages, model.High,
		`\b[MNO][A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{27,}\b`,
		"Reset this token in the Discord Developer Portal → Bot → Reset Token immediately. Whoever holds it has full control of the bot account."),

	// Databases
	r("neon-connection-string", "Neon Postgres connection string", gDB, model.Critical, `\bpostgres(?:ql)?://[^\s:@/"'<>]+:[^\s@/"'<>]+@[A-Za-z0-9.\-]*neon\.tech`, rotateDB),
	r("upstash-redis-url", "Upstash Redis connection URL", gDB, model.Critical, `\brediss?://[^\s:@/"'<>]*:[^\s@/"'<>]+@[A-Za-z0-9.\-]*upstash\.io`, rotateDB),
	r("upstash-rest-token", "Upstash REST token", gDB, model.High, `(?i)upstash[_a-z\-]*token["']?\s*[:=]\s*["'][A-Za-z0-9=_\-]{30,}["']`, rotate).validated(randomQuoted(12)),
	r("turso-auth-token", "Turso database auth token", gDB, model.Critical,
		`(?s)libsql://[a-z0-9\-.]+\.turso\.io.{0,300}?auth[Tt]oken["']?\s*[:=]\s*["']eyJ[A-Za-z0-9_\-.]{30,}["']|TURSO_AUTH_TOKEN["']?\s*[:=]\s*["']?eyJ[A-Za-z0-9_\-.]{30,}`, rotate),
	r("database-url-with-password", "Database connection string with password", gDB, model.Critical,
		`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[^\s:@/"'<>]+:[^\s@/"'<>]{3,}@[A-Za-z0-9.\-]+`, rotateDB).validated(realDBURL),

	// Auth
	r("clerk-secret-key-live", "Clerk live secret key", gAuth, model.Critical, `\bsk_live_[A-Za-z0-9]{40,}\b`, rotate).validated(notStripe),
	r("clerk-secret-key-test", "Clerk development secret key", gAuth, model.High, `\bsk_test_[A-Za-z0-9]{40,}\b`, rotate).validated(notStripe),
	r("auth0-client-secret", "Auth0 client secret", gAuth, model.High, `(?i)auth0[_\-.]?client[_\-.]?secret["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{40,}["']`,
		"Rotate the client secret in the Auth0 dashboard. Single-page apps must use the PKCE flow with no client secret; keep secrets in your backend.").validated(randomQuoted(16)),

	// Backend platforms
	r("appwrite-api-key", "Appwrite server API key", gBackend, model.Critical, `\bstandard_[a-f0-9]{128}\b`, rotate),
	r("appwrite-set-key", "Appwrite server key hardcoded via setKey()", gBackend, model.High, `\.setKey\(\s*["'][^"']{20,}["']\s*\)`, rotate).validated(randomQuoted(10)),
	r("convex-deploy-key", "Convex deploy key", gBackend, model.Critical, `\b(?:prod|dev|preview):[a-z0-9\-]+\|[A-Za-z0-9+/=_\-]{40,}`, rotate),
	r("shopify-token", "Shopify access token", gBackend, model.High, `\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`,
		"Rotate this token in the Shopify admin (Apps → app credentials or custom app). Anyone holding it can read and modify store data through the Admin API."),
	r("notion-token", "Notion integration token", gBackend, model.High, `\bsecret_[A-Za-z0-9]{43}\b`, rotate),

	// Other
	r("private-key", "Private key block", gOther, model.Critical, `-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`, rotate),
	genericRule,
}

// Rules returns a copy of all registered rules.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	return out
}

// --- generic high-entropy detection ---

const (
	entropyMinLen   = 24  // shorter strings are ambiguous even for humans
	entropyMaxLen   = 256 // longer strings are assets, not credentials
	entropyMinBits  = 4.5 // Shannon bits per char; random base64 is ≈5.5+
	entropyMaxFinds = 10  // cap the report to the strongest candidates
)

// literalRe captures quoted strings made only of characters that appear in
// real credentials (alnum, base64 padding, JWT dots). URLs, paths and prose
// fail the charset and never become candidates.
var literalRe = re(`["']([A-Za-z0-9+/=_.\-]{24,256})["']`)

// envRe captures unquoted values from KEY=value lines (.env files and shell
// exports), so repo-mode entropy checks are not blind without quotes.
var envRe = re(`(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]{2,}\s*=\s*["']?([A-Za-z0-9+/=_.\-]{24,256})["']?\s*$`)

var uuidRe = re(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// encodedPrefixes are base64 signatures of binary assets and embedded source
// code — common bundle artifacts, never credentials.
var encodedPrefixes = []string{
	"iVBORw0KGgo",                                                        // PNG
	"/9j/4AAQ",                                                           // JPEG
	"PHN2Zy",                                                             // SVG
	"JVBERi0x",                                                           // PDF
	"UklGR",                                                              // WebP
	"R0lGOD",                                                             // GIF
	"SUQz",                                                               // MP3
	"ZnVuY3Rpb24", "dmFy", "Y29uc3Q", "aW1wb3J0", "ZXhwb3J0", "bW9kdWxl", // JS source
	"data:",
}

// genericRule backs the "possible unnamed secret" findings. It has no regex
// pattern; Scan runs the entropy heuristic separately.
var genericRule = Rule{
	ID:       "high-entropy-string",
	Name:     "Possible unnamed secret (high-entropy string)",
	Group:    gOther,
	Severity: model.Low,
	Fix:      "Keydra found a long, random-looking string that matches no known key format. Check whether it is a credential: if so, rotate it and move it server-side. Build artifacts such as hashes or encoded assets can be ignored.",
}

// entropy computes Shannon entropy in bits per character.
func entropy(s string) float64 {
	n := float64(len(s))
	if n == 0 {
		return 0
	}
	freq := map[byte]int{}
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var e float64
	for _, c := range freq {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// assetExtRe matches static-asset file extensions — candidates that end in
// one are file paths (bundled chunks, manifests), not credentials.
var assetExtRe = re(`(?i)\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|map|json|html?|txt|xml|csv|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf)$`)

// alphabetConstants are character-set tables embedded in every base64/base32
// codec bundle. They look maximally random (every character is unique) but
// are constants, never credentials.
var alphabetConstants = map[string]bool{
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=": true, // base64
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":  true, // base64url
	"-_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":  true, // base64url, other order
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":    true, // base64 without padding
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567":                                  true, // base32
	"abcdefghijklmnopqrstuvwxyz234567":                                  true, // base32 lowercase
	"0123456789ABCDEFGHJKMNPQRSTVWXYZ":                                  true, // Crockford base32
	"0123456789abcdefghjkmnpqrstvwxyz":                                  true, // Crockford base32 lower
	"0123456789abcdefghijklmnopqrstuvwxyz":                              true, // hex digits
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ":                              true, // hex digits upper
}

// entropyCandidate filters quoted strings before entropy scoring: length
// bounds, mixed character classes, and known-harmless shapes (hex hashes,
// UUIDs, encoded binary assets, asset paths).
func entropyCandidate(v string) bool {
	if len(v) < entropyMinLen || len(v) > entropyMaxLen {
		return false
	}
	// A leading slash or asset extension marks a file path — Next.js build
	// IDs, bundled chunk names, manifests. Credentials never look like that.
	if strings.HasPrefix(v, "/") || assetExtRe.MatchString(v) {
		return false
	}
	var upper, lower, digit, hexable bool
	hexable = true
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'z':
			lower = true
			if r > 'f' {
				hexable = false
			}
		case r >= 'A' && r <= 'Z':
			upper = true
			if r > 'F' {
				hexable = false
			}
		default:
			hexable = false
		}
	}
	if hexable || !upper || !lower || !digit {
		return false // hex hashes, or strings without mixed classes
	}
	if uuidRe.MatchString(v) {
		return false
	}
	if alphabetConstants[v] {
		return false // codec character-set tables embedded in bundles
	}
	for _, p := range encodedPrefixes {
		if strings.Contains(v, p) {
			return false
		}
	}
	return entropy(v) >= entropyMinBits
}

// genericMatches reports the strongest high-entropy quoted strings that no
// specific rule already covers, capped at entropyMaxFinds to keep bundles
// full of build artifacts from flooding the report.
func genericMatches(body string, known []string, seen map[string]bool) []Match {
	var cands []string
	uniq := map[string]bool{}
	for _, rx := range []*regexp.Regexp{literalRe, envRe} {
		for _, m := range rx.FindAllStringSubmatch(body, -1) {
			v := m[1]
			if uniq[v] || !entropyCandidate(v) {
				continue
			}
			uniq[v] = true
			skip := false
			for _, k := range known {
				if strings.Contains(v, k) || strings.Contains(k, v) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			cands = append(cands, v)
		}
	}
	// Highest entropy first, stable so equal-entropy candidates keep scan
	// order and output stays deterministic.
	sort.SliceStable(cands, func(i, j int) bool { return entropy(cands[i]) > entropy(cands[j]) })
	var out []Match
	for _, v := range cands {
		if len(out) == entropyMaxFinds {
			break
		}
		key := genericRule.ID + "\x00" + v
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Match{Rule: genericRule, Value: v})
	}
	return out
}

// Scan runs every rule over body and returns unique matches ordered by
// severity (highest first).
func Scan(body string) []Match {
	seen := map[string]bool{}
	var out []Match
	var known []string
	for _, rule := range rules {
		if rule.Pattern == nil {
			continue // the generic high-entropy rule runs separately below
		}
		for _, v := range rule.Pattern.FindAllString(body, -1) {
			if rule.Validate != nil && !rule.Validate(v) {
				continue
			}
			key := rule.ID + "\x00" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			known = append(known, v)
			out = append(out, Match{Rule: rule, Value: v})
		}
	}
	out = append(out, genericMatches(body, known, seen)...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rule.Severity > out[j].Rule.Severity })
	return out
}

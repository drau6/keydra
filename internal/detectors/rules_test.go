package detectors

import (
	"encoding/base64"
	"strings"
	"testing"
)

// fakeJWT builds a syntactically valid JWT with the given payload so no
// secret-shaped literal lives in this file.
func fakeJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + strings.Repeat("x", 43)
}

func TestScanFindsKnownPatterns(t *testing.T) {
	// Built at runtime so this file never contains a secret-shaped literal.
	stripe := "sk_" + "live_" + strings.Repeat("a", 24)
	midtrans := "Mid-" + "server-" + strings.Repeat("b", 24)
	body := `const a="` + stripe + `"; const b="` + midtrans + `"; const c="not-a-key"`

	got := Scan(body)
	ids := map[string]bool{}
	for _, m := range got {
		ids[m.Rule.ID] = true
	}
	for _, want := range []string{"stripe-secret-key", "midtrans-server-key"} {
		if !ids[want] {
			t.Errorf("expected rule %s to match", want)
		}
	}
	if len(got) != 2 {
		t.Errorf("expected 2 matches, got %d", len(got))
	}
}

func TestScanDeduplicates(t *testing.T) {
	k := "sk_" + "live_" + strings.Repeat("c", 24)
	if n := len(Scan(k + " " + k)); n != 1 {
		t.Fatalf("expected 1 unique match, got %d", n)
	}
}

func idsOf(body string) map[string]bool {
	out := map[string]bool{}
	for _, m := range Scan(body) {
		out[m.Rule.ID] = true
	}
	return out
}

// randish builds an n-character alphanumeric string with high character
// diversity at runtime, so no secret-shaped literal lives in this file.
func randish(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0:
			sb.WriteByte('a' + byte(i*7%26))
		case 1:
			sb.WriteByte('A' + byte(i*5%26))
		default:
			sb.WriteByte('0' + byte(i*3%10))
		}
	}
	return sb.String()
}

func TestServiceSpecificDetectors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
		not  []string
	}{
		{"neon", "postgres" + "ql://appuser:" + "Zx9kQ2mLpW" + "@ep-cool-123.us-east-2.aws.neon.tech/neondb",
			[]string{"neon-connection-string"}, []string{"database-url-with-password"}},
		{"upstash redis", "redis" + "s://default:" + "AbCdEf123456" + "@fit-owl-1234.upstash.io:6379",
			[]string{"upstash-redis-url"}, []string{"database-url-with-password"}},
		{"upstash rest token", `UPSTASH_REDIS_REST_TOKEN="` + randish(48) + `"`,
			[]string{"upstash-rest-token"}, nil},
		{"turso", `createClient({url:"libsql://my-db-user.turso.io",authToken:"eyJ` + strings.Repeat("h", 40) + `"})`,
			[]string{"turso-auth-token"}, nil},
		{"auth0", `auth0ClientSecret: "` + randish(48) + `"`,
			[]string{"auth0-client-secret"}, nil},
		{"mongo", "mongodb+srv://user:" + "Pa55w0rdReal" + "@cluster0.abcde.mongodb.net/app",
			[]string{"database-url-with-password"}, nil},
		{"clerk is not stripe", "sk_" + "live_" + strings.Repeat("A", 40),
			[]string{"clerk-secret-key-live"}, []string{"stripe-secret-key"}},
		{"stripe is not clerk", "sk_" + "live_51" + strings.Repeat("b", 40),
			[]string{"stripe-secret-key"}, []string{"clerk-secret-key-live"}},
		{"clerk dev key", "sk_" + "test_" + strings.Repeat("C", 40),
			[]string{"clerk-secret-key-test"}, nil},
		{"stripe test keys ignored", "sk_" + "test_51" + strings.Repeat("d", 40),
			nil, []string{"clerk-secret-key-test", "stripe-secret-key"}},
		{"placeholder db urls ignored",
			"postgres://user:password@localhost:5432/db postgres://u:<password>@db.example.com/x mysql://root:" + "hunter22xx" + "@127.0.0.1/app",
			nil, []string{"database-url-with-password"}},
		{"openai legacy key", `sk-` + randish(48),
			[]string{"openai-key"}, nil},
		{"openai repeated filler rejected", `sk-` + strings.Repeat("a", 48),
			nil, []string{"openai-key"}},
		{"openai proj key", `sk-proj-` + strings.Repeat("a", 44),
			[]string{"openai-key"}, nil},
		{"resend key", `re_` + randish(40),
			[]string{"resend-key"}, nil},
		{"resend repeated filler rejected", `re_` + strings.Repeat("x", 40),
			nil, []string{"resend-key"}},
		{"appwrite setKey", `.setKey("` + randish(30) + `")`,
			[]string{"appwrite-set-key"}, nil},
		{"appwrite setKey filler rejected", `.setKey("` + strings.Repeat("x", 30) + `")`,
			nil, []string{"appwrite-set-key"}},
		{"appwrite setKey env ref rejected", `.setKey("process.env.APPWRITE_API_KEY")`,
			nil, []string{"appwrite-set-key"}},
		{"aws secret key", `AWS_SECRET_ACCESS_KEY=` + randish(40),
			[]string{"aws-secret-access-key"}, nil},
		{"aws sha1-looking value rejected", `AWS_SECRET_ACCESS_KEY=` + strings.Repeat("a1", 20),
			nil, []string{"aws-secret-access-key"}},
		{"upstash token filler rejected", `UPSTASH_REDIS_REST_TOKEN="` + strings.Repeat("x", 32) + `"`,
			nil, []string{"upstash-rest-token"}},
		{"auth0 filler rejected", `auth0ClientSecret: "` + strings.Repeat("x", 48) + `"`,
			nil, []string{"auth0-client-secret"}},
		{"generic high-entropy string", `const blob="` + randish(48) + `"`,
			[]string{"high-entropy-string"}, nil},
		{"hex hash ignored", `const commit="` + strings.Repeat("d3", 20) + `"`,
			nil, []string{"high-entropy-string"}},
		{"encoded asset ignored", `const img="iVBORw0KGgo` + randish(40) + `"`,
			nil, []string{"high-entropy-string"}},
		{"unquoted env value", "BACKUP_TOKEN=" + randish(40) + "\n",
			[]string{"high-entropy-string"}, nil},
		{"github fine-grained pat", "github_" + "pat_" + randish(30),
			[]string{"github-pat"}, nil},
		{"gitlab token", "glpat-" + randish(24),
			[]string{"gitlab-token"}, nil},
		{"npm token", "npm_" + randish(36),
			[]string{"npm-token"}, nil},
		{"digitalocean token", "dop_v1_" + strings.Repeat("ab", 32),
			[]string{"digitalocean-token"}, nil},
		{"shopify token", "shp" + "at_" + strings.Repeat("ab", 16),
			[]string{"shopify-token"}, nil},
		{"square token", "sq0" + "atp-" + randish(22),
			[]string{"square-token"}, nil},
		{"razorpay key", "rzp_" + "live_" + randish(16),
			[]string{"razorpay-key"}, nil},
		{"mailgun key", "key-" + strings.Repeat("ab", 16),
			[]string{"mailgun-key"}, nil},
		{"discord bot token", "M" + randish(26) + "." + randish(6) + "." + randish(30),
			[]string{"discord-bot-token"}, nil},
		{"discord webhook is not a bot token", "https://discord.com/api/webhooks/1234567890/" + randish(30),
			[]string{"discord-webhook"}, []string{"discord-bot-token"}},
		{"groq key", "gsk_" + randish(24),
			[]string{"groq-key"}, nil},
		{"perplexity key", "pplx-" + randish(32),
			[]string{"perplexity-key"}, nil},
		{"huggingface token", "hf_" + randish(36),
			[]string{"huggingface-token"}, nil},
		{"notion token", "secret_" + randish(43),
			[]string{"notion-token"}, nil},
		{"jwt-shaped token flagged by entropy heuristic", `const k="` + fakeJWT(`{"iss":"example-issuer","sub":"1234567890","aud":"api","exp":2065394249,"iat":1749818249}`) + `"`,
			[]string{"high-entropy-string"}, nil},
		{"next.js asset path is not a secret", `const m="/_next/static/` + randish(22) + `/_ssgManifest.js"`,
			nil, []string{"high-entropy-string"}},
		{"asset filename anywhere is not a secret", `const c="` + randish(16) + `." + "chunk.js"`,
			nil, []string{"high-entropy-string"}},
		{"base64 alphabet constant is not a secret", `const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="`,
			nil, []string{"high-entropy-string"}},
		{"base64url alphabet constant is not a secret", `const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"`,
			nil, []string{"high-entropy-string"}},
	}
	for _, c := range cases {
		got := idsOf(c.body)
		for _, id := range c.want {
			if !got[id] {
				t.Errorf("%s: expected %s, got %v", c.name, id, got)
			}
		}
		for _, id := range c.not {
			if got[id] {
				t.Errorf("%s: %s must not match, got %v", c.name, id, got)
			}
		}
	}
}

func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range Catalog() {
		if seen[e.ID] {
			t.Errorf("duplicate catalog id %s", e.ID)
		}
		seen[e.ID] = true
	}
	for _, rule := range Rules() {
		if !seen[rule.ID] {
			t.Errorf("rule %s missing from catalog", rule.ID)
		}
	}
	var sb strings.Builder
	Markdown(&sb)
	if !strings.Contains(sb.String(), "`clerk-secret-key-live`") || !strings.Contains(sb.String(), "| ID | Severity |") {
		t.Error("markdown output incomplete")
	}
}

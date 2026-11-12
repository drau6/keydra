// Package validate confirms leaked secrets against their provider APIs. This
// is opt-in (--validate): each check is a single read-only request that
// reports only whether the credential is active, rejected or unverifiable.
// Nothing about the key is stored beyond the returned result.
package validate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Result is the outcome of one live check.
type Result int

const (
	Unknown Result = iota // no endpoint, network problem or unexpected status
	Valid                 // the provider accepted the credential
	Invalid               // the provider rejected it: revoked or fake
)

func (r Result) String() string {
	switch r {
	case Valid:
		return "active"
	case Invalid:
		return "rejected"
	default:
		return "unverified"
	}
}

// Provider describes one read-only "is this key alive" request.
type Provider struct {
	Endpoint string
	Method   string // default GET
	Bearer   bool   // Authorization: Bearer <value>
	Basic    string // basic-auth username (password = value), e.g. mailgun's "api"
	Headers  map[string]string
	// Invalid lists statuses that mean "revoked or fake". Default 401 and 403.
	// Narrow-scoped keys (e.g. Stripe restricted) can get 403 while valid, so
	// those providers list only 401.
	Invalid []int
	// AuthPrefix overrides the default "Bearer" authorization scheme
	// (Discord bot tokens require "Bot").
	AuthPrefix string
	// JSONOK means 2xx only counts as valid when the body has ok=true (Slack).
	JSONOK bool
}

var providers = map[string]Provider{
	"openai-key":            {Endpoint: "https://api.openai.com/v1/models", Bearer: true},
	"groq-key":              {Endpoint: "https://api.groq.com/openai/v1/models", Bearer: true},
	"anthropic-key":         {Endpoint: "https://api.anthropic.com/v1/models", Headers: map[string]string{"anthropic-version": "2023-06-01", "x-api-key": ""}},
	"stripe-secret-key":     {Endpoint: "https://api.stripe.com/v1/charges?limit=1", Bearer: true},
	"stripe-restricted-key": {Endpoint: "https://api.stripe.com/v1/charges?limit=1", Bearer: true, Invalid: []int{401}}, // 403 = scope-limited but valid
	"github-token":          {Endpoint: "https://api.github.com/user", Bearer: true},
	"github-pat":            {Endpoint: "https://api.github.com/user", Bearer: true},
	"gitlab-token":          {Endpoint: "https://gitlab.com/api/v4/user", Bearer: true},
	"huggingface-token":     {Endpoint: "https://huggingface.co/api/whoami-v2", Bearer: true},
	"sendgrid-key":          {Endpoint: "https://api.sendgrid.com/v3/scopes", Bearer: true},
	"resend-key":            {Endpoint: "https://api.resend.com/domains", Bearer: true},
	"mailgun-key":           {Endpoint: "https://api.mailgun.net/v3/domains", Basic: "api"},
	"discord-bot-token":     {Endpoint: "https://discord.com/api/v10/users/@me", Bearer: true, AuthPrefix: "Bot"},
	"digitalocean-token":    {Endpoint: "https://api.digitalocean.com/v2/account", Bearer: true},
	"notion-token":          {Endpoint: "https://api.notion.com/v1/users", Bearer: true, Headers: map[string]string{"Notion-Version": "2022-06-28"}},
	"slack-token":           {Endpoint: "https://slack.com/api/auth.test", Method: "POST", Bearer: true, JSONOK: true},
	"clerk-secret-key-live": {Endpoint: "https://api.clerk.com/v1/application", Bearer: true},
	"clerk-secret-key-test": {Endpoint: "https://api.clerk.com/v1/application", Bearer: true},
}

// Lookup reports whether ruleID has a live-validation endpoint.
func Lookup(ruleID string) (Provider, bool) {
	p, ok := providers[ruleID]
	return p, ok
}

var client = &http.Client{}

// Check asks the provider whether value is an active credential.
func Check(ctx context.Context, ruleID, value string, timeout time.Duration) Result {
	p, ok := providers[ruleID]
	if !ok {
		return Unknown
	}
	return check(ctx, p, value, timeout)
}

// check is the testable core; tests pass their own Provider pointing at a
// local httptest server.
func check(ctx context.Context, p Provider, value string, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := p.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, p.Endpoint, nil)
	if err != nil {
		return Unknown
	}
	switch {
	case p.Bearer:
		prefix := p.AuthPrefix
		if prefix == "" {
			prefix = "Bearer"
		}
		req.Header.Set("Authorization", prefix+" "+value)
	case p.Basic != "":
		req.SetBasicAuth(p.Basic, value)
	}
	for k, v := range p.Headers {
		if v == "" { // placeholder header: the value is the credential itself
			req.Header.Set(k, value)
		} else {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("User-Agent", "keydra (leaked-credential check)")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Unknown
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if p.JSONOK {
			var body struct {
				OK bool `json:"ok"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&body); err == nil && !body.OK {
				return Invalid
			}
		}
		return Valid
	}
	invalid := p.Invalid
	if len(invalid) == 0 {
		invalid = []int{http.StatusUnauthorized, http.StatusForbidden}
	}
	for _, code := range invalid {
		if resp.StatusCode == code {
			return Invalid
		}
	}
	return Unknown
}

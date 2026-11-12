package repo

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/drau6/keydra/internal/model"
)

// Check runs all repository-level checks. These are heuristics over source
// text; they complement (not replace) scanning the deployed app.
func Check(files []File) []model.Finding {
	var out []model.Finding
	out = append(out, envFiles(files)...)
	out = append(out, publicEnvVars(files)...)
	if usesSupabase(files) {
		out = append(out, supabaseSQL(files)...)
	}
	out = append(out, firebaseRules(files)...)
	out = append(out, convexFunctions(files)...)
	return out
}

// ---- .env files ----

func envFiles(files []File) []model.Finding {
	var out []model.Finding
	for _, f := range files {
		if !f.IsEnv || f.Ignored {
			continue
		}
		out = append(out, model.Finding{
			ID:       "env-file-not-ignored",
			Title:    fmt.Sprintf("%s is not covered by .gitignore", path.Base(f.Rel)),
			Severity: model.High,
			Category: "Repository",
			Detail:   "Environment files normally hold server secrets. If this file is committed, every secret in it is in your git history.",
			Location: f.Rel,
			Fix:      "Add \".env*\" and \"!.env.example\" to .gitignore. If it was already committed: `git rm --cached " + f.Rel + "`, then rotate every key inside and purge history.",
		})
	}
	return out
}

// ---- secrets behind browser-exposed env prefixes ----

var publicEnvRe = regexp.MustCompile(`\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*?(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|OPENAI|ANTHROPIC|STRIPE_SK|DEEPSEEK|GEMINI|SENDGRID|RESEND)[A-Z0-9_]*`)

func publicEnvVars(files []File) []model.Finding {
	first := map[string]string{}
	for _, f := range files {
		for _, name := range publicEnvRe.FindAllString(f.Body, -1) {
			if _, ok := first[name]; !ok {
				first[name] = f.Rel
			}
		}
	}
	names := make([]string, 0, len(first))
	for n := range first {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []model.Finding
	for _, n := range names {
		out = append(out, model.Finding{
			ID:       "secret-in-public-env",
			Title:    fmt.Sprintf("%s will be bundled into the browser", n),
			Severity: model.High,
			Category: "Repository",
			Detail:   "Variables with this prefix are inlined into client-side JavaScript at build time, so anything secret stored in them is public.",
			Evidence: n,
			Location: first[n],
			Fix:      "Rename it without the public prefix, read it only in server code (API route, server action, edge function), and rotate the key if it was ever deployed.",
		})
	}
	return out
}

// ---- Supabase SQL migrations ----

var (
	sqlLineComment  = regexp.MustCompile(`--[^\n]*`)
	sqlBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	createTableRe   = regexp.MustCompile(`(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?([a-z0-9_]+)"?\.)?"?([a-z0-9_]+)"?`)
	enableRLSRe     = regexp.MustCompile(`(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:"?([a-z0-9_]+)"?\.)?"?([a-z0-9_]+)"?\s+enable\s+row\s+level\s+security`)
	disableRLSRe    = regexp.MustCompile(`(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:"?([a-z0-9_]+)"?\.)?"?([a-z0-9_]+)"?\s+disable\s+row\s+level\s+security`)
	policyRe        = regexp.MustCompile(`(?is)^\s*create\s+policy\s+(?:"[^"]*"|\S+)\s+on\s+(?:"?([a-z0-9_]+)"?\.)?"?([a-z0-9_]+)"?(.*)$`)
	alwaysTrueRe    = regexp.MustCompile(`(?is)\b(?:using|with\s+check)\s*\(\s*true\s*\)`)
	writeClauseRe   = regexp.MustCompile(`(?is)\bfor\s+(?:insert|update|delete|all)\b`)
	forClauseRe     = regexp.MustCompile(`(?is)\bfor\s+(?:select|insert|update|delete|all)\b`)
	withCheckTrueRe = regexp.MustCompile(`(?is)\bwith\s+check\s*\(\s*true\s*\)`)
	rolesRe         = regexp.MustCompile(`(?is)\bto\s+([a-z_"]+(?:\s*,\s*[a-z_"]+)*)`)
	anonOrPublicRe  = regexp.MustCompile(`(?i)\b(?:anon|public)\b`)
)

func usesSupabase(files []File) bool {
	for _, f := range files {
		if strings.Contains(f.Rel, "supabase/") ||
			strings.Contains(f.Body, "@supabase/") ||
			strings.Contains(f.Body, "supabase.co") ||
			strings.Contains(f.Body, "auth.uid()") {
			return true
		}
	}
	return false
}

func publicTable(schema string) bool { return schema == "" || strings.EqualFold(schema, "public") }

func supabaseSQL(files []File) []model.Finding {
	created := map[string]string{} // table -> file
	enabled := map[string]bool{}
	var out []model.Finding

	for _, f := range files {
		if !strings.HasSuffix(strings.ToLower(f.Rel), ".sql") {
			continue
		}
		sql := sqlBlockComment.ReplaceAllString(sqlLineComment.ReplaceAllString(f.Body, ""), "")

		for _, m := range createTableRe.FindAllStringSubmatch(sql, -1) {
			if publicTable(m[1]) {
				if _, ok := created[strings.ToLower(m[2])]; !ok {
					created[strings.ToLower(m[2])] = f.Rel
				}
			}
		}
		for _, m := range enableRLSRe.FindAllStringSubmatch(sql, -1) {
			if publicTable(m[1]) {
				enabled[strings.ToLower(m[2])] = true
			}
		}
		for _, m := range disableRLSRe.FindAllStringSubmatch(sql, -1) {
			if publicTable(m[1]) {
				out = append(out, model.Finding{
					ID:       "supabase-rls-disabled",
					Title:    fmt.Sprintf("Row Level Security is explicitly disabled on %q", m[2]),
					Severity: model.High,
					Category: "Supabase",
					Detail:   "With RLS off, the public anon key can read and write this table through the API.",
					Location: f.Rel,
					Fix:      fmt.Sprintf("alter table public.%s enable row level security;", m[2]),
				})
			}
		}

		for _, stmt := range strings.Split(sql, ";") {
			m := policyRe.FindStringSubmatch(stmt)
			if m == nil || !publicTable(m[1]) {
				continue
			}
			rest := m[3]
			if !alwaysTrueRe.MatchString(rest) {
				continue
			}
			if r := rolesRe.FindStringSubmatch(rest); r != nil && !anonOrPublicRe.MatchString(r[1]) {
				continue // limited to authenticated / service_role
			}
			write := writeClauseRe.MatchString(rest) || withCheckTrueRe.MatchString(rest) || !forClauseRe.MatchString(rest)
			sev, what := model.Medium, "read"
			if write {
				sev, what = model.High, "read and write"
			}
			out = append(out, model.Finding{
				ID:       "supabase-policy-open",
				Title:    fmt.Sprintf("Policy on %q lets anyone %s", m[2], what),
				Severity: sev,
				Category: "Supabase",
				Detail:   "The policy condition is always true and is not limited to logged-in users. Fine for genuinely public data, dangerous otherwise.",
				Location: f.Rel,
				Fix:      "Restrict the role (`to authenticated`) and scope rows, e.g. `using (auth.uid() = user_id)`.",
			})
		}
	}

	tables := make([]string, 0, len(created))
	for t := range created {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		if enabled[t] {
			continue
		}
		out = append(out, model.Finding{
			ID:       "supabase-rls-missing",
			Title:    fmt.Sprintf("Table %q has no Row Level Security in your migrations", t),
			Severity: model.SeverityForName(t),
			Category: "Supabase",
			Detail:   "Supabase exposes public tables through its API. Without RLS the anon key can read and write them. (Heuristic: only SQL files in this repo were checked.)",
			Location: created[t],
			Fix:      fmt.Sprintf("alter table public.%s enable row level security;\n-- then add explicit policies, e.g.\ncreate policy \"own rows\" on public.%s for all to authenticated using (auth.uid() = user_id);", t, t),
		})
	}
	return out
}

// ---- Firebase security rules ----

var (
	fsAllowTrueRe = regexp.MustCompile(`(?i)allow\s+([a-z, ]+?)\s*:\s*if\s+true\b`)
	fsTestModeRe  = regexp.MustCompile(`(?i)request\.time\s*<\s*timestamp\.date\(`)
	rtdbOpenRe    = regexp.MustCompile(`(?i)"\.(read|write)"\s*:\s*(?:true|"true")`)
	writeOpsRe    = regexp.MustCompile(`(?i)write|create|update|delete`)
)

func firebaseRules(files []File) []model.Finding {
	var out []model.Finding
	for _, f := range files {
		base := strings.ToLower(path.Base(f.Rel))
		switch {
		case strings.HasSuffix(base, ".rules"):
			for _, m := range fsAllowTrueRe.FindAllStringSubmatch(f.Body, -1) {
				sev, what := model.High, "read"
				if writeOpsRe.MatchString(m[1]) {
					sev, what = model.Critical, "write"
				}
				out = append(out, model.Finding{
					ID:       "firebase-rules-open",
					Title:    fmt.Sprintf("%s rule allows anyone to %s (%s)", base, what, strings.TrimSpace(m[1])),
					Severity: sev,
					Category: "Firebase",
					Detail:   "`if true` grants access to every visitor on the internet, logged in or not.",
					Location: f.Rel,
					Fix:      "Require login and ownership, e.g. `allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`",
				})
			}
			if fsTestModeRe.MatchString(f.Body) {
				out = append(out, model.Finding{
					ID:       "firebase-rules-test-mode",
					Title:    fmt.Sprintf("%s still uses time-limited test-mode rules", base),
					Severity: model.High,
					Category: "Firebase",
					Detail:   "Test-mode rules are fully open until the given date, and many projects forget to replace them.",
					Location: f.Rel,
					Fix:      "Replace the `request.time < timestamp.date(...)` rule with authentication- and ownership-based rules.",
				})
			}
		case base == "database.rules.json":
			for _, m := range rtdbOpenRe.FindAllStringSubmatch(f.Body, -1) {
				sev := model.High
				if strings.EqualFold(m[1], "write") {
					sev = model.Critical
				}
				out = append(out, model.Finding{
					ID:       "firebase-rules-open",
					Title:    fmt.Sprintf("Realtime Database rules set .%s to true", strings.ToLower(m[1])),
					Severity: sev,
					Category: "Firebase",
					Detail:   "Anyone can access the data without logging in.",
					Location: f.Rel,
					Fix:      "Use `\"auth != null\"` at minimum, and per-user rules such as `\"auth.uid === $uid\"`.",
				})
			}
		}
	}
	return out
}

// ---- Convex functions ----

var convexFnRe = regexp.MustCompile(`export\s+const\s+(\w+)\s*=\s*(?:query|mutation|action)\(`)

func convexFunctions(files []File) []model.Finding {
	var out []model.Finding
	for _, f := range files {
		parts := strings.Split(f.Rel, "/")
		inConvex := false
		for _, p := range parts[:len(parts)-1] {
			if p == "convex" {
				inConvex = true
			}
			if p == "_generated" {
				inConvex = false
				break
			}
		}
		ext := strings.ToLower(path.Ext(f.Rel))
		if !inConvex || (ext != ".ts" && ext != ".js" && ext != ".tsx" && ext != ".mts") {
			continue
		}
		var names []string
		for _, m := range convexFnRe.FindAllStringSubmatch(f.Body, -1) {
			names = append(names, m[1])
		}
		if len(names) == 0 || strings.Contains(f.Body, "getUserIdentity") || strings.Contains(f.Body, "getAuthUserId") {
			continue
		}
		shown := names
		if len(shown) > 8 {
			shown = shown[:8]
		}
		out = append(out, model.Finding{
			ID:       "convex-public-functions-no-auth",
			Title:    fmt.Sprintf("Public Convex functions in %s never check the caller's identity", path.Base(f.Rel)),
			Severity: model.Medium,
			Category: "Convex",
			Detail:   "query/mutation/action functions are callable by anyone with your deployment URL. (Heuristic: confirm whether this data is meant to be public.)",
			Evidence: strings.Join(shown, ", "),
			Location: f.Rel,
			Fix:      "Add `const identity = await ctx.auth.getUserIdentity(); if (!identity) throw new Error(\"Not authenticated\");`, scope data by identity.subject, and use internalQuery/internalMutation for server-only logic.",
		})
	}
	return out
}

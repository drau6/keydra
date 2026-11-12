// Package extractor pulls backend configuration (Supabase, Firebase) out of
// client-side code so it can be checked for unsafe exposure.
package extractor

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Supabase key roles.
const (
	RoleAnon        = "anon"
	RoleServiceRole = "service_role"
	RolePublishable = "publishable"
	RoleSecret      = "secret"
)

// SupabaseKey is a key found in client code.
type SupabaseKey struct {
	Value string
	Role  string
}

// Firebase groups the web-config fields found in client code.
type Firebase struct {
	APIKeys      []string
	ProjectIDs   []string
	DatabaseURLs []string
	Buckets      []string
}

// Config is everything extracted from one or more files.
type Config struct {
	SupabaseURLs []string
	SupabaseKeys []SupabaseKey
	Tables       []string
	Firebase     Firebase
	Collections  []string
	Appwrite     Appwrite
	PocketBase   []string
	Convex       Convex
}

var (
	sbURLRe    = regexp.MustCompile(`https://[a-z0-9]{15,30}\.supabase\.(?:co|in)`)
	jwtRe      = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)
	sbPubRe    = regexp.MustCompile(`\bsb_publishable_[A-Za-z0-9_\-]{20,}`)
	sbSecretRe = regexp.MustCompile(`\bsb_secret_[A-Za-z0-9_\-]{20,}`)
	tableRe    = regexp.MustCompile("\\.from\\(\\s*[\"'`]([A-Za-z0-9_]+)[\"'`]\\s*\\)")

	fbKeyRe    = regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)
	fbProjRe   = regexp.MustCompile(`projectId["']?\s*:\s*["']([a-z0-9\-]{4,40})["']`)
	fbDBRe     = regexp.MustCompile(`databaseURL["']?\s*:\s*["'](https://[A-Za-z0-9.\-]+)/?["']`)
	fbBucketRe = regexp.MustCompile(`storageBucket["']?\s*:\s*["']([A-Za-z0-9._\-]+)["']`)
	fbColRe    = regexp.MustCompile(`collection\(\s*(?:[A-Za-z_$][\w$.]*\s*,\s*)?["']([A-Za-z0-9_\-]+)["']\s*[,)]`)
)

// Extract scans body for backend configuration.
func Extract(body string) Config {
	var c Config
	c.SupabaseURLs = sbURLRe.FindAllString(body, -1)

	for _, tok := range jwtRe.FindAllString(body, -1) {
		if role, ok := supabaseJWTRole(tok); ok {
			c.SupabaseKeys = append(c.SupabaseKeys, SupabaseKey{Value: tok, Role: role})
		}
	}
	for _, k := range sbPubRe.FindAllString(body, -1) {
		c.SupabaseKeys = append(c.SupabaseKeys, SupabaseKey{Value: k, Role: RolePublishable})
	}
	for _, k := range sbSecretRe.FindAllString(body, -1) {
		c.SupabaseKeys = append(c.SupabaseKeys, SupabaseKey{Value: k, Role: RoleSecret})
	}

	for _, m := range tableRe.FindAllStringSubmatchIndex(body, -1) {
		start := m[0] - 24
		if start < 0 {
			start = 0
		}
		if strings.Contains(body[start:m[0]], "storage") {
			continue // supabase.storage.from("bucket"), not a table
		}
		c.Tables = append(c.Tables, body[m[2]:m[3]])
	}

	c.Firebase.APIKeys = fbKeyRe.FindAllString(body, -1)
	c.Firebase.ProjectIDs = submatches(fbProjRe, body)
	c.Firebase.DatabaseURLs = submatches(fbDBRe, body)
	c.Firebase.Buckets = submatches(fbBucketRe, body)
	c.Collections = submatches(fbColRe, body)

	c.Appwrite = extractAppwrite(body)
	c.PocketBase = submatches(pbRe, body)
	c.Convex = extractConvex(body)
	return c.normalize()
}

// Merge combines two configs, de-duplicating every field.
func (c Config) Merge(o Config) Config {
	c.SupabaseURLs = append(c.SupabaseURLs, o.SupabaseURLs...)
	c.SupabaseKeys = append(c.SupabaseKeys, o.SupabaseKeys...)
	c.Tables = append(c.Tables, o.Tables...)
	c.Collections = append(c.Collections, o.Collections...)
	c.Firebase.APIKeys = append(c.Firebase.APIKeys, o.Firebase.APIKeys...)
	c.Firebase.ProjectIDs = append(c.Firebase.ProjectIDs, o.Firebase.ProjectIDs...)
	c.Firebase.DatabaseURLs = append(c.Firebase.DatabaseURLs, o.Firebase.DatabaseURLs...)
	c.Firebase.Buckets = append(c.Firebase.Buckets, o.Firebase.Buckets...)
	c.Appwrite.Endpoints = append(c.Appwrite.Endpoints, o.Appwrite.Endpoints...)
	c.Appwrite.Projects = append(c.Appwrite.Projects, o.Appwrite.Projects...)
	c.Appwrite.Collections = append(c.Appwrite.Collections, o.Appwrite.Collections...)
	c.Appwrite.Tables = append(c.Appwrite.Tables, o.Appwrite.Tables...)
	c.Appwrite.Buckets = append(c.Appwrite.Buckets, o.Appwrite.Buckets...)
	c.PocketBase = append(c.PocketBase, o.PocketBase...)
	c.Convex.URLs = append(c.Convex.URLs, o.Convex.URLs...)
	c.Convex.Functions = append(c.Convex.Functions, o.Convex.Functions...)
	return c.normalize()
}

// HasSupabase reports whether a Supabase project and a usable key were found.
func (c Config) HasSupabase() bool { return len(c.SupabaseURLs) > 0 && len(c.SupabaseKeys) > 0 }

// HasFirebase reports whether any Firebase configuration was found.
func (c Config) HasFirebase() bool {
	f := c.Firebase
	return len(f.ProjectIDs) > 0 || len(f.DatabaseURLs) > 0 || len(f.Buckets) > 0
}

func (c Config) normalize() Config {
	c.SupabaseURLs = uniq(c.SupabaseURLs)
	c.Tables = uniq(c.Tables)
	c.Collections = uniq(c.Collections)
	c.Firebase.APIKeys = uniq(c.Firebase.APIKeys)
	c.Firebase.ProjectIDs = uniq(c.Firebase.ProjectIDs)
	c.Firebase.DatabaseURLs = uniq(c.Firebase.DatabaseURLs)
	c.Firebase.Buckets = uniq(c.Firebase.Buckets)
	c.Appwrite.Endpoints = uniq(c.Appwrite.Endpoints)
	c.Appwrite.Projects = uniq(c.Appwrite.Projects)
	c.Appwrite.Collections = uniqDocRefs(c.Appwrite.Collections)
	c.Appwrite.Tables = uniqDocRefs(c.Appwrite.Tables)
	c.Appwrite.Buckets = uniq(c.Appwrite.Buckets)
	c.PocketBase = uniq(c.PocketBase)
	c.Convex.URLs = uniq(c.Convex.URLs)
	c.Convex.Functions = uniq(c.Convex.Functions)

	seen := map[string]bool{}
	var keys []SupabaseKey
	for _, k := range c.SupabaseKeys {
		if !seen[k.Value] {
			seen[k.Value] = true
			keys = append(keys, k)
		}
	}
	c.SupabaseKeys = keys
	return c
}

// supabaseJWTRole decodes a JWT payload (without verifying it) and returns
// its role if the token looks like a Supabase key.
func supabaseJWTRole(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", false
	}
	var p struct {
		Iss  string `json:"iss"`
		Ref  string `json:"ref"`
		Role string `json:"role"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return "", false
	}
	if !strings.Contains(p.Iss, "supabase") && p.Ref == "" {
		return "", false
	}
	switch p.Role {
	case RoleAnon, RoleServiceRole:
		return p.Role, true
	}
	return "", false
}

func submatches(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, s := range in {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

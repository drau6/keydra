package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/drau6/keydra/internal/model"
)

func TestIgnoreMatching(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env*\n!.env.example\nnode_modules/\n/dist\n# comment\n"), 0o644)
	ig := loadIgnore(dir)

	cases := map[string]bool{
		".env":                 true,
		".env.local":           true,
		"apps/web/.env":        true,
		".env.example":         false,
		"node_modules/x/y.js":  true,
		"src/node_modules":     false, // dir-only pattern must not match a file
		"dist/app.js":          true,
		"packages/dist/app.js": false, // anchored to the root
		"src/main.ts":          false,
	}
	for rel, want := range cases {
		if got := ig.matches(rel); got != want {
			t.Errorf("matches(%q) = %v, want %v", rel, got, want)
		}
	}
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func idSet(fs []model.Finding) map[string]model.Finding {
	m := map[string]model.Finding{}
	for _, f := range fs {
		m[f.ID+"|"+f.Title] = f
	}
	return m
}

func has(fs []model.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestChecks(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".env.production", "SOMETHING=1\n") // no .gitignore: not ignored
	write(t, root, "src/config.ts", "const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n")
	write(t, root, "supabase/migrations/001.sql", `
-- create table public.commented_out (id int);
create table public.profiles (id uuid primary key);
create table if not exists public.posts (id int);
alter table public.posts enable row level security;
create policy "everyone reads" on public.posts for select using (true);
create policy "authed all" on public.posts for all to authenticated using (true);
create policy "anyone writes" on public.posts for insert to anon with check (true);
create table auth_helper.sessions (id int);
`)
	write(t, root, "firestore.rules", "service cloud.firestore { match /{d=**} { allow read, write: if true; } }")
	write(t, root, "database.rules.json", `{"rules":{".read":true,".write":false}}`)
	write(t, root, "convex/tasks.ts", "export const list = query({ handler: async (ctx) => [] });\nexport const secure = internalQuery({});")
	write(t, root, "convex/safe.ts", "export const me = query({ handler: async (ctx) => ctx.auth.getUserIdentity() });")
	write(t, root, "convex/_generated/api.ts", "export const x = query(")

	files, _, err := Walk(root, WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := Check(files)

	for _, id := range []string{
		"env-file-not-ignored", "secret-in-public-env", "supabase-rls-missing",
		"supabase-policy-open", "firebase-rules-open", "convex-public-functions-no-auth",
	} {
		if !has(got, id) {
			t.Errorf("missing finding %s", id)
		}
	}

	set := idSet(got)
	if f, ok := set[`supabase-rls-missing|Table "profiles" has no Row Level Security in your migrations`]; !ok || f.Severity != model.Critical {
		t.Errorf("profiles should be missing RLS at critical severity: %+v", f)
	}
	for _, f := range got {
		switch {
		case f.ID == "supabase-rls-missing" && (f.Title == `Table "posts" has no Row Level Security in your migrations` ||
			f.Title == `Table "commented_out" has no Row Level Security in your migrations` ||
			f.Title == `Table "sessions" has no Row Level Security in your migrations`):
			t.Errorf("false positive: %s", f.Title)
		case f.ID == "convex-public-functions-no-auth" && f.Location != "convex/tasks.ts":
			t.Errorf("unexpected convex finding at %s", f.Location)
		}
	}
	// open read policy = medium, open insert policy = high; authenticated-only policy is ignored.
	var policies []model.Severity
	for _, f := range got {
		if f.ID == "supabase-policy-open" {
			policies = append(policies, f.Severity)
		}
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 open policies, got %v", policies)
	}
}

func TestCleanRepo(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".gitignore", ".env*\n")
	write(t, root, ".env", "STRIPE=1\n")
	write(t, root, "src/app.ts", "console.log('hello')\n")
	files, _, _ := Walk(root, WalkOptions{})
	if got := Check(files); len(got) != 0 {
		t.Fatalf("expected no findings, got %+v", got)
	}
}

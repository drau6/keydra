package detectors

import (
	"fmt"
	"io"
	"strings"
)

// Entry describes one check for documentation and `keydra rules`.
type Entry struct {
	ID       string
	Severity string
	Name     string
	Group    string
	Where    string // "URL", "Repo" or "URL + repo"
}

const (
	whereURL  = "URL"
	whereRepo = "Repo"
	whereBoth = "URL + repo"
)

// checks lists every non-regex check, in documentation order.
var checks = []Entry{
	{"supabase-service-key-exposed", "critical", "Supabase service_role / secret key shipped to the browser", "Supabase", whereBoth},
	{"supabase-table-exposed", "high/critical", "Table readable with the public anon key (missing or weak RLS)", "Supabase", whereURL},
	{"supabase-rls-missing", "high/critical", "Table created in SQL migrations without Row Level Security", "Supabase", whereRepo},
	{"supabase-rls-disabled", "high", "Row Level Security explicitly disabled", "Supabase", whereRepo},
	{"supabase-policy-open", "medium/high", "Policy with using (true) open to anon/public", "Supabase", whereRepo},

	{"firebase-rtdb-open", "high/critical", "Realtime Database readable without login", "Firebase", whereURL},
	{"firebase-firestore-open", "high/critical", "Firestore collection readable without login", "Firebase", whereURL},
	{"firebase-storage-listable", "high", "Storage bucket listable without login", "Firebase", whereURL},
	{"firebase-rules-open", "high/critical", "Rules with `if true` or .read/.write: true", "Firebase", whereRepo},
	{"firebase-rules-test-mode", "high", "Time-limited test-mode rules still in place", "Firebase", whereRepo},

	{"appwrite-collection-exposed", "high/critical", "Collection readable with the \"Any\" role (Databases API)", "Appwrite", whereURL},
	{"appwrite-table-exposed", "high/critical", "Table readable with the \"Any\" role (TablesDB API)", "Appwrite", whereURL},
	{"appwrite-bucket-exposed", "high", "Storage bucket listable without login", "Appwrite", whereURL},

	{"pocketbase-collection-exposed", "high/critical", "Collection with an empty (public) List rule", "PocketBase", whereURL},
	{"pocketbase-admin-ui-public", "low", "Admin dashboard reachable from the internet", "PocketBase", whereURL},

	{"convex-public-query-returns-data", "medium", "Query returns data to unauthenticated callers", "Convex", whereURL},
	{"convex-public-functions-no-auth", "medium", "Public functions that never check the caller's identity (heuristic)", "Convex", whereRepo},

	{"env-file-not-ignored", "high", ".env file not covered by .gitignore", "Repository", whereRepo},
	{"secret-in-public-env", "high", "Secret stored in a NEXT_PUBLIC_ / VITE_ / REACT_APP_ / EXPO_PUBLIC_ variable", "Repository", whereRepo},

	{"source-map-exposed", "low", "Public JavaScript source map", "Exposure", whereURL},
}

// Catalog returns every check: secret detectors first (grouped by service),
// then backend and repository checks.
func Catalog() []Entry {
	var out []Entry
	for _, g := range groupOrder {
		for _, rule := range rules {
			if rule.Group == g {
				out = append(out, Entry{rule.ID, rule.Severity.String(), rule.Name, "Secrets · " + g, whereBoth})
			}
		}
	}
	return append(out, checks...)
}

// Markdown writes the catalog as grouped Markdown tables.
func Markdown(w io.Writer) {
	var group string
	for _, e := range Catalog() {
		if e.Group != group {
			if group != "" {
				fmt.Fprintln(w)
			}
			group = e.Group
			fmt.Fprintf(w, "**%s**\n\n| ID | Severity | Detects | Where |\n|---|---|---|---|\n", group)
		}
		fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", e.ID, e.Severity, strings.ReplaceAll(e.Name, "|", "\\|"), e.Where)
	}
}

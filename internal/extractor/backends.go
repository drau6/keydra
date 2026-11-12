package extractor

import "regexp"

// DocRef points at an Appwrite collection.
type DocRef struct {
	Database   string
	Collection string
}

// Appwrite groups Appwrite SDK configuration found in client code.
type Appwrite struct {
	Endpoints   []string
	Projects    []string
	Collections []DocRef
	Tables      []DocRef // TablesDB API; DocRef.Collection holds the table ID
	Buckets     []string
}

// Convex groups Convex deployment URLs and function paths ("module:name").
type Convex struct {
	URLs      []string
	Functions []string
}

var (
	awEndpointRe = regexp.MustCompile(`setEndpoint\(\s*["'](https?://[^"']+)["']\s*\)`)
	awProjectRe  = regexp.MustCompile(`setProject\(\s*["']([^"']+)["']\s*\)`)
	awDocsRe     = regexp.MustCompile(`listDocuments\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']`)
	awDocsObjRe  = regexp.MustCompile(`listDocuments\(\s*\{\s*databaseId\s*:\s*["']([^"']+)["']\s*,\s*collectionId\s*:\s*["']([^"']+)["']`)
	awRowsRe     = regexp.MustCompile(`listRows\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']`)
	awRowsObjRe  = regexp.MustCompile(`listRows\(\s*\{\s*databaseId\s*:\s*["']([^"']+)["']\s*,\s*tableId\s*:\s*["']([^"']+)["']`)
	awBucketRe   = regexp.MustCompile(`listFiles\(\s*(?:\{\s*bucketId\s*:\s*)?["']([^"']+)["']`)

	pbRe = regexp.MustCompile(`new\s+PocketBase\(\s*["'](https?://[^"']+)["']`)

	cvxURLRe = regexp.MustCompile(`https://[a-z0-9\-]+\.convex\.cloud`)
	cvxFnRe  = regexp.MustCompile(`(?:makeFunctionReference|useQuery|\.query)\(\s*["']([A-Za-z0-9_./]+:[A-Za-z0-9_]+)["']`)
)

func extractAppwrite(body string) Appwrite {
	a := Appwrite{
		Endpoints: submatches(awEndpointRe, body),
		Projects:  submatches(awProjectRe, body),
		Buckets:   submatches(awBucketRe, body),
	}
	for _, re := range []*regexp.Regexp{awDocsRe, awDocsObjRe} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			a.Collections = append(a.Collections, DocRef{Database: m[1], Collection: m[2]})
		}
	}
	for _, re := range []*regexp.Regexp{awRowsRe, awRowsObjRe} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			a.Tables = append(a.Tables, DocRef{Database: m[1], Collection: m[2]})
		}
	}
	return a
}

func extractConvex(body string) Convex {
	return Convex{
		URLs:      cvxURLRe.FindAllString(body, -1),
		Functions: submatches(cvxFnRe, body),
	}
}

// HasAppwrite reports whether an Appwrite project was found.
func (c Config) HasAppwrite() bool { return len(c.Appwrite.Projects) > 0 }

// HasPocketBase reports whether a PocketBase instance URL was found.
func (c Config) HasPocketBase() bool { return len(c.PocketBase) > 0 }

// HasConvex reports whether a Convex deployment URL was found.
func (c Config) HasConvex() bool { return len(c.Convex.URLs) > 0 }

func uniqDocRefs(in []DocRef) []DocRef {
	seen := map[DocRef]bool{}
	var out []DocRef
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

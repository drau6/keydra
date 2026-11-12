package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/drau6/keydra/internal/extractor"
	"github.com/drau6/keydra/internal/model"
)

const rtdbRules = `{
  "rules": {
    ".read": false,
    ".write": false,
    "users": { "$uid": { ".read": "auth.uid === $uid", ".write": "auth.uid === $uid" } }
  }
}`

// Firebase checks Realtime Database, Firestore and Storage for public access.
func (p *Prober) Firebase(ctx context.Context, cfg extractor.Config) Result {
	var res Result
	fb := cfg.Firebase

	dbs := append([]string(nil), fb.DatabaseURLs...)
	if len(dbs) == 0 && len(fb.APIKeys) > 0 {
		for _, id := range capList(fb.ProjectIDs, 2) {
			dbs = append(dbs, fmt.Sprintf("https://%s-default-rtdb.firebaseio.com", id))
		}
	}
	for _, db := range capList(dbs, 3) {
		p.rtdb(ctx, db, &res)
	}

	apiKey := ""
	if len(fb.APIKeys) > 0 {
		apiKey = fb.APIKeys[0]
	}
	for _, pid := range capList(fb.ProjectIDs, 2) {
		for _, col := range capList(cfg.Collections, p.MaxTargets) {
			if ctx.Err() != nil {
				return res
			}
			p.firestore(ctx, pid, col, apiKey, &res)
		}
	}

	for _, bucket := range capList(fb.Buckets, 3) {
		p.storage(ctx, bucket, &res)
	}
	return res
}

func (p *Prober) rtdb(ctx context.Context, dbURL string, res *Result) {
	u := strings.TrimRight(dbURL, "/") + "/.json?shallow=true"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := p.do(ctx, req)
	if err != nil {
		res.warn(fmt.Sprintf("firebase rtdb %s: %v", dbURL, err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return // 401 / 404: locked or absent
	}
	body := strings.TrimSpace(string(peek(resp, 8<<10)))

	var nodes []string
	var top map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &top) == nil {
		for k := range top {
			nodes = append(nodes, k)
		}
		sort.Strings(nodes)
	}

	sev, detail, evidence := model.High, "Database rules allow public reads; the database is currently empty.", "GET /.json?shallow=true → 200 (null)"
	if len(nodes) > 0 {
		sev = model.Critical
		detail = "Anyone can read the entire Realtime Database without logging in."
		evidence = fmt.Sprintf("GET /.json?shallow=true → 200, top-level nodes: %s", strings.Join(capList(nodes, 8), ", "))
	}
	res.add(model.Finding{
		ID:       "firebase-rtdb-open",
		Title:    "Firebase Realtime Database is publicly readable",
		Severity: sev,
		Category: "Firebase",
		Detail:   detail,
		Evidence: evidence,
		Location: dbURL,
		Fix:      "Replace the rules in Firebase Console → Realtime Database → Rules:\n" + rtdbRules,
	})
}

func (p *Prober) firestore(ctx context.Context, projectID, collection, apiKey string, res *Result) {
	u := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s?pageSize=1",
		url.PathEscape(projectID), url.PathEscape(collection))
	if apiKey != "" {
		u += "&key=" + url.QueryEscape(apiKey)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := p.do(ctx, req)
	if err != nil {
		res.warn(fmt.Sprintf("firestore %s/%s: %v", projectID, collection, err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	if !strings.Contains(string(peek(resp, 4<<10)), `"documents"`) {
		return // readable but empty, or unrelated response
	}
	res.add(model.Finding{
		ID:       "firebase-firestore-open",
		Title:    fmt.Sprintf("Firestore collection %q is publicly readable", collection),
		Severity: severityFor(collection),
		Category: "Firebase",
		Detail:   "Documents in this collection can be listed without authentication.",
		Evidence: fmt.Sprintf("GET /v1/projects/%s/databases/(default)/documents/%s → 200 with documents", projectID, collection),
		Location: "firestore.googleapis.com",
		Fix: "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n" +
			"    match /" + collection + "/{id} {\n      allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;\n    }\n  }\n}",
	})
}

func (p *Prober) storage(ctx context.Context, bucket string, res *Result) {
	u := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o?maxResults=1", url.PathEscape(bucket))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := p.do(ctx, req)
	if err != nil {
		res.warn(fmt.Sprintf("firebase storage %s: %v", bucket, err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body := string(peek(resp, 4<<10))
	if !strings.Contains(body, `"items"`) && !strings.Contains(body, `"prefixes"`) {
		return
	}
	res.add(model.Finding{
		ID:       "firebase-storage-listable",
		Title:    "Firebase Storage bucket is publicly listable",
		Severity: model.High,
		Category: "Firebase",
		Detail:   "Anyone can list the files in this bucket, which often contains uploads and personal documents.",
		Evidence: fmt.Sprintf("GET /v0/b/%s/o → 200 with items", bucket),
		Location: bucket,
		Fix: "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n" +
			"    match /{allPaths=**} { allow read, write: if request.auth != null; }\n  }\n}",
	})
}

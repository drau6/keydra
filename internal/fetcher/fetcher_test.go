package fetcher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// site builds a small multi-page site and counts hits to a dangerous URL.
func site(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var logoutHits atomic.Int32
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>"+body+"</html>") }
	}
	mux.HandleFunc("/", page(`<a href="/a">a</a> <a href="/b?x=1#top">b</a> <a href="/logout">out</a>
		<a href="/logo.png">img</a> <a href="https://other.example/x">ext</a> <a href="mailto:x@y.z">m</a>
		<script src="/app.js"></script>`))
	mux.HandleFunc("/a", page(`<a href="/c">c</a> <a href="/">home</a> <script src="/a.js"></script>`))
	mux.HandleFunc("/b", page(`<p>b</p>`))
	mux.HandleFunc("/c", page(`<script src="/c.js"></script>`))
	mux.HandleFunc("/hidden", page(`<script src="/hidden.js"></script>`))
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) { logoutHits.Add(1) })
	for _, js := range []string{"app", "a", "c", "hidden"} {
		js := js
		mux.HandleFunc("/"+js+".js", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintf(w, "console.log(%q)", js) })
	}
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<urlset><url><loc>http://%s/hidden</loc></url><url><loc>http://%s/a</loc></url></urlset>`, r.Host, r.Host)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &logoutHits
}

func crawl(t *testing.T, base string, opts Options) *Result {
	t.Helper()
	opts.Timeout = 5 * time.Second
	opts.Delay = time.Millisecond
	res, err := New(opts).Crawl(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func paths(base string, urls []string) string {
	var out []string
	for _, u := range urls {
		out = append(out, strings.TrimPrefix(u, base))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestDepthControlsPages(t *testing.T) {
	srv, logout := site(t)
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"default is one page", Options{}, "/"},
		{"depth 1", Options{Depth: 1}, "/"},
		{"depth 2 follows links, skips unsafe/static/external", Options{Depth: 2}, "/,/a,/b?x=1"},
		{"depth 3 reaches /c", Options{Depth: 3}, "/,/a,/b?x=1,/c"},
		{"max-pages caps the crawl", Options{Depth: 3, MaxPages: 2}, "/,/a"},
		{"sitemap adds unlinked pages", Options{Sitemap: true}, "/,/a,/hidden"},
	}
	for _, c := range cases {
		res := crawl(t, srv.URL+"/", c.opts)
		if got := paths(srv.URL, res.Pages); got != c.want {
			t.Errorf("%s: pages = %s, want %s", c.name, got, c.want)
		}
	}
	if n := logout.Load(); n != 0 {
		t.Errorf("crawler requested /logout %d times", n)
	}
}

func TestScriptsFromAllPagesAreCollected(t *testing.T) {
	srv, _ := site(t)
	res := crawl(t, srv.URL+"/", Options{Depth: 3})
	var js []string
	for _, a := range res.Assets {
		if a.Kind == KindJS && !strings.Contains(a.URL, "#") {
			js = append(js, a.URL)
		}
	}
	if got := paths(srv.URL, js); got != "/a.js,/app.js,/c.js" {
		t.Errorf("scripts = %s", got)
	}
}

func TestDepthWarnsOnClientRenderedApps(t *testing.T) {
	spa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<html><div id="root"></div><script src="/x.js"></script></html>`)
	}))
	defer spa.Close()
	res := crawl(t, spa.URL, Options{Depth: 3})
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "no internal links") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a client-rendered warning, got %v", res.Warnings)
	}
}

func TestRedirectStaysOnSameHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html><script src=\"/app.js\"></script></html>")
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "console.log('ok')")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := crawl(t, srv.URL, Options{})
	if len(res.Assets) != 2 || !strings.HasSuffix(res.Assets[1].URL, "/app.js") {
		t.Fatalf("same-host redirect should be followed, assets = %+v", res.Assets)
	}
}

func TestCrossHostRedirectBlocked(t *testing.T) {
	var nextHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/next", func(w http.ResponseWriter, _ *http.Request) {
		nextHits.Add(1)
		fmt.Fprint(w, "<html></html>")
	})
	var redirect string
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirect, http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// The same server, reached through a different hostname, must still count
	// as a different host: redirects may not leave the scanned origin.
	_, port, ok := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	if !ok {
		t.Fatalf("unexpected test server URL %q", srv.URL)
	}
	redirect = "http://localhost:" + port + "/next"

	_, err := New(Options{Timeout: 5 * time.Second, Delay: time.Millisecond}).Crawl(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "different host") {
		t.Fatalf("cross-host redirect should be blocked, got %v", err)
	}
	if n := nextHits.Load(); n != 0 {
		t.Errorf("redirect target was requested %d times", n)
	}
}

func TestCheckRedirectBlocksPrivateTargets(t *testing.T) {
	f := &Fetcher{baseHost: "127.0.0.1"}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9000/internal", nil)
	if err := f.checkRedirect(req, nil); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("private redirect should be blocked, got %v", err)
	}

	f.allowLocal = true
	if err := f.checkRedirect(req, nil); err != nil {
		t.Fatalf("local development should allow private redirects, got %v", err)
	}

	f.baseHost = ""
	if err := f.checkRedirect(req, nil); err == nil {
		t.Fatal("a redirect before any crawl origin must be blocked")
	}
}

func TestTooManyRedirects(t *testing.T) {
	f := &Fetcher{baseHost: "example.com"}
	via := make([]*http.Request, 5)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err := f.checkRedirect(req, via); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("redirect loop should be capped, got %v", err)
	}
}

func TestResolveBlocksPrivateThirdPartyTargets(t *testing.T) {
	base, err := url.Parse("https://example.com/app.js")
	if err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{opts: Options{ThirdParty: true}}
	for _, raw := range []string{
		"http://127.0.0.1:9000/secret.js",
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.google.internal/computeMetadata/v1/",
	} {
		if got := f.resolve(base, raw); got != "" {
			t.Errorf("resolve(%q) = %q, want it blocked", raw, got)
		}
	}
	if got := f.resolve(base, "https://cdn.example.net/app.js"); got == "" {
		t.Error("public third-party script should still resolve")
	}

	f.allowLocal = true
	if got := f.resolve(base, "http://127.0.0.1:9000/secret.js"); got == "" {
		t.Error("a local target should still be able to reference a private script")
	}
}

func TestThirdPartyAssetRedirectWithinItsHost(t *testing.T) {
	f := &Fetcher{baseHost: "example.com", opts: Options{ThirdParty: true}}
	orig := httptest.NewRequest(http.MethodGet, "https://cdn.example.net/app.js", nil)
	next := httptest.NewRequest(http.MethodGet, "https://cdn.example.net/app.v2.js", nil)
	if err := f.checkRedirect(next, []*http.Request{orig}); err != nil {
		t.Fatalf("asset redirect within its own host should be allowed, got %v", err)
	}

	other := httptest.NewRequest(http.MethodGet, "https://other.example.org/app.js", nil)
	if err := f.checkRedirect(other, []*http.Request{orig}); err == nil {
		t.Fatal("asset redirect to an unrelated host should still be blocked")
	}
}

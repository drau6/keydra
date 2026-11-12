package fetcher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

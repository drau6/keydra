package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSameHost(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"Example.COM", "example.com", true},
		{"example.com.", "example.com", true},
		{"www.example.com", "example.com", false},
		{"127.0.0.1", "127.0.0.1", true},
		{"", "", true},
	}
	for _, c := range cases {
		if got := SameHost(c.a, c.b); got != c.want {
			t.Errorf("SameHost(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSameSite(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com", "www.example.com", true},
		{"WWW.Example.com.", "example.com", true},
		{"example.com", "api.example.com", false},
		{"localhost", "127.0.0.1", false},
		{"example.com", "example.net", false},
	}
	for _, c := range cases {
		if got := SameSite(c.a, c.b); got != c.want {
			t.Errorf("SameSite(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestIsPrivateHost(t *testing.T) {
	private := []string{
		"localhost", "LOCALHOST.", "app.localhost", "printer.local",
		"metadata", "metadata.google.internal", "host.docker.internal",
		"db.internal", "nas.home.arpa",
		"127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1",
	}
	for _, host := range private {
		if !IsPrivateHost(host) {
			t.Errorf("IsPrivateHost(%q) = false, want true", host)
		}
	}

	public := []string{"", "example.com", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, host := range public {
		if IsPrivateHost(host) {
			t.Errorf("IsPrivateHost(%q) = true, want false", host)
		}
	}
}

func TestValidateHTTPURL(t *testing.T) {
	ok := []struct {
		raw  string
		want string
	}{
		{"https://example.com/app?q=1#section", "https://example.com/app?q=1"},
		{" http://example.com ", "http://example.com"},
	}
	for _, c := range ok {
		got, err := ValidateHTTPURL(c.raw, false)
		if err != nil || got != c.want {
			t.Errorf("ValidateHTTPURL(%q) = %q, %v; want %q, nil", c.raw, got, err, c.want)
		}
	}

	bad := []string{
		"",
		"not a url",
		"ftp://example.com/file",
		"https://user:pass@example.com",
		"http://127.0.0.1:5432",
		"http://localhost:3000",
		"http://10.0.0.5",
	}
	for _, raw := range bad {
		if got, err := ValidateHTTPURL(raw, false); err == nil {
			t.Errorf("ValidateHTTPURL(%q) = %q, nil; want an error", raw, got)
		}
	}

	if got, err := ValidateHTTPURL("http://127.0.0.1:5432/rest/v1", true); err != nil || got != "http://127.0.0.1:5432/rest/v1" {
		t.Errorf("local URL with allowPrivate should pass, got %q, %v", got, err)
	}
}

type mapResolver map[string][]net.IPAddr

func (m mapResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	addrs, ok := m[host]
	if !ok {
		return nil, fmt.Errorf("test resolver: no addresses for %s", host)
	}
	return addrs, nil
}

func TestDialerBlocksLiteralPrivateIP(t *testing.T) {
	d := &Dialer{}
	_, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("DialContext = %v, want ErrPrivateAddress", err)
	}
}

func TestDialerBlocksResolvedPrivateAddress(t *testing.T) {
	d := &Dialer{Resolver: mapResolver{
		"looks-public.test": {{IP: net.ParseIP("127.0.0.1")}},
	}}
	_, err := d.DialContext(context.Background(), "tcp", "looks-public.test:80")
	if !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("DialContext = %v, want ErrPrivateAddress", err)
	}
}

func TestDialerAllowsPrivateWhenEnabled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
			close(accepted)
		}
	}()

	d := &Dialer{AllowPrivate: true}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext with AllowPrivate = %v", err)
	}
	conn.Close()
	<-accepted
}

func TestNewTransportBlocksResolvedPrivateAddress(t *testing.T) {
	tr := NewTransport(func() bool { return false }, mapResolver{
		"looks-public.test": {{IP: net.ParseIP("10.0.0.7")}},
	})
	tr.Proxy = nil // keep the test independent of proxy environment variables
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	_, err := client.Get("http://looks-public.test/")
	if !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("GET = %v, want ErrPrivateAddress", err)
	}
}

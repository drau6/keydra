// Package netutil contains small helpers for keeping scans on public,
// expected hosts instead of letting target-controlled URLs reach local or
// internal services.
package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPrivateAddress is returned when a connection would reach a local or
// private address and private destinations are not allowed.
var ErrPrivateAddress = errors.New("private or local address blocked")

// CanonicalHost lower-cases a hostname and removes a trailing root dot.
func CanonicalHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// SameHost reports whether two hostnames refer to the same host (ignoring case
// and a trailing dot).
func SameHost(a, b string) bool {
	return CanonicalHost(a) == CanonicalHost(b)
}

// SameSite reports whether two hostnames are the same site for redirect
// purposes. It also treats the common "www." alias as the same site so that
// scanning example.com is not broken by its canonical redirect to
// www.example.com.
func SameSite(a, b string) bool {
	a, b = CanonicalHost(a), CanonicalHost(b)
	if a == b {
		return true
	}
	return strings.TrimPrefix(a, "www.") == strings.TrimPrefix(b, "www.")
}

// IsPrivateIP reports whether ip is local, loopback, link-local, private or
// otherwise unsuitable as a remote scan destination.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Carrier-grade NAT (100.64.0.0/10) is not covered by net.IP.IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return false
}

// IsPrivateHost reports whether host is clearly local, loopback, link-local,
// private or a well-known internal name. It intentionally errs on the side of
// blocking: callers can opt in with AllowPrivate for local development.
func IsPrivateHost(host string) bool {
	h := CanonicalHost(host)
	if h == "" {
		return false
	}
	switch h {
	case "localhost", "metadata", "metadata.google.internal", "instance-data",
		"host.docker.internal", "host.containers.internal":
		return true
	}
	if strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".home.arpa") {
		return true
	}
	return IsPrivateIP(net.ParseIP(h))
}

// ValidateHTTPURL parses raw, requires an http(s) URL without embedded
// credentials, and rejects private destinations unless allowPrivate is set.
// It returns a normalized URL string for use in requests.
//
// ValidateHTTPURL only inspects the literal hostname; use Dialer (or
// NewTransport) to also reject public-looking names that resolve to private
// addresses.
func ValidateHTTPURL(raw string, allowPrivate bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("credentials in URL are not allowed")
	}
	if !allowPrivate && IsPrivateHost(u.Hostname()) {
		return "", ErrPrivateAddress
	}
	u.Fragment = ""
	return u.String(), nil
}

// Resolver is the subset of net.Resolver used by Dialer. Tests can supply a
// resolver that maps names to loopback addresses without touching DNS.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Dialer refuses to connect to local/private addresses unless AllowPrivate is
// true. It resolves hostnames itself and dials the resolved IP, so a second
// DNS answer cannot move the connection to a private address between the
// check and the connect.
type Dialer struct {
	AllowPrivate bool
	Resolver     Resolver
	NetDialer    *net.Dialer
}

// DialContext implements the net.Dialer signature.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	nd := d.NetDialer
	if nd == nil {
		nd = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	if d.AllowPrivate {
		return nd.DialContext(ctx, network, address)
	}

	dialIP := func(ip net.IP) (net.Conn, error) {
		return nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateAddress, host)
		}
		return dialIP(ip)
	}

	res := d.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	addrs, err := res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	var firstErr error
	for _, addr := range addrs {
		if IsPrivateIP(addr.IP) {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: %s resolves to %s", ErrPrivateAddress, host, addr.IP)
			}
			continue
		}
		conn, err := dialIP(addr.IP)
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no addresses found for %s", host)
	}
	return nil, firstErr
}

// NewTransport returns a clone of http.DefaultTransport with a Dialer that
// checks the current private-address policy for every connection. allowPrivate
// is called per dial, so callers can set their policy after constructing the
// client. A nil resolver uses the system resolver.
func NewTransport(allowPrivate func() bool, resolver Resolver) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &Dialer{AllowPrivate: allowPrivate(), Resolver: resolver}
		return d.DialContext(ctx, network, address)
	}
	return tr
}

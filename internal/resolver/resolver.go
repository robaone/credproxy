package resolver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/providers"
)

const defaultSentinel = "CREDPROXY_TOKEN"
const credentialCacheTTL = 5 * time.Minute
const maxBodySize = 10 * 1024 * 1024

type cacheEntry struct {
	value   string
	expires time.Time
}

type Resolver struct {
	cfg   *config.Config
	reg   *providers.Registry
	cache map[string]cacheEntry
	mu    sync.Mutex
	re    *regexp.Regexp
}

func New(cfg *config.Config, reg *providers.Registry) *Resolver {
	r := &Resolver{
		cfg:   cfg,
		reg:   reg,
		cache: make(map[string]cacheEntry),
	}
	r.SetSentinel(defaultSentinel)
	return r
}

// SetSentinel accepts an optional ":name" suffix selecting a named credential
// for the host; the bare sentinel selects the host's default credential.
func (r *Resolver) SetSentinel(s string) {
	r.re = regexp.MustCompile(regexp.QuoteMeta(s) + `(?::([A-Za-z0-9_-]+))?`)
}

// Resolve looks up an arbitrary credential URI through the provider registry.
// It is the host-agnostic counterpart to ResolveRequest and is used for
// resolving env var values at startup.
func (r *Resolver) Resolve(ctx context.Context, uri string) (string, error) {
	return r.reg.Resolve(ctx, uri)
}

func (r *Resolver) IsHostAllowed(host string) bool {
	return r.cfg.IsHostAllowed(host)
}

func (r *Resolver) ResolveRequest(req *http.Request, host string) error {
	uris, ok := r.cfg.CredentialURIs(host)
	if !ok {
		return nil
	}

	s := &substitution{r: r, ctx: req.Context(), host: host, uris: uris}

	if err := s.headers(req.Header); err != nil {
		return err
	}

	if req.URL.RawQuery != "" && r.re.MatchString(req.URL.RawQuery) {
		query, err := s.expand(req.URL.RawQuery)
		if err != nil {
			return err
		}
		req.URL.RawQuery = query
	}

	if req.Body != nil && req.Body != http.NoBody {
		if err := s.body(req); err != nil {
			return fmt.Errorf("substituting body: %w", err)
		}
	}

	return nil
}

func (r *Resolver) resolveURI(ctx context.Context, uri string) (string, error) {
	r.mu.Lock()
	if entry, ok := r.cache[uri]; ok && time.Now().Before(entry.expires) {
		r.mu.Unlock()
		return entry.value, nil
	}
	r.mu.Unlock()

	val, err := r.reg.Resolve(ctx, uri)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.cache[uri] = cacheEntry{value: val, expires: time.Now().Add(credentialCacheTTL)}
	r.mu.Unlock()
	return val, nil
}

// substitution expands sentinels for one request. Credentials are resolved
// lazily, so a sentinel-free request never triggers a provider lookup.
type substitution struct {
	r    *Resolver
	ctx  context.Context
	host string
	uris map[string]string
}

func (s *substitution) headers(h http.Header) error {
	for key, values := range h {
		for i, val := range values {
			// Plain sentinel check first — the common case. continue so we don't
			// also run the encoded path against the original val below.
			if s.r.re.MatchString(val) {
				out, err := s.expand(val)
				if err != nil {
					return err
				}
				h[key][i] = out
				continue
			}
			// For Authorization headers, some clients base64-encode credentials
			// before sending (e.g. curl -u for Basic auth, elasticsearch-py for
			// ApiKey auth). Try decoding each token to find an encoded sentinel.
			// TODO: expand to all headers if we encounter encoded credentials
			// outside of Authorization.
			if key == "Authorization" {
				newVal, ok, err := s.encodedAuthHeader(val)
				if err != nil {
					return err
				}
				if ok {
					h[key][i] = newVal
				}
			}
		}
	}
	return nil
}

// encodedAuthHeader handles clients that base64-encode credentials
// before sending them in an Authorization header. It tries to base64-decode each
// space-separated token; if a decoded token contains a sentinel, it substitutes
// and re-encodes that token. All matching tokens are substituted.
//
// Only standard base64 is attempted. URL-safe base64 (-/_) is not currently
// handled — add base64.URLEncoding fallback here if that becomes necessary.
//
// Returns the modified header value and true if any substitution was made,
// or "", false if no encoded sentinel was found.
func (s *substitution) encodedAuthHeader(val string) (string, bool, error) {
	tokens := strings.Split(val, " ")
	modified := false
	for i, token := range tokens {
		if token == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			continue
		}
		if !s.r.re.Match(decoded) {
			continue
		}
		substituted, err := s.expand(string(decoded))
		if err != nil {
			return "", false, err
		}
		tokens[i] = base64.StdEncoding.EncodeToString([]byte(substituted))
		modified = true
	}
	if !modified {
		return "", false, nil
	}
	return strings.Join(tokens, " "), true, nil
}

func (s *substitution) body(req *http.Request) error {
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize+1))
	req.Body.Close()
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}
	if len(body) > maxBodySize {
		return fmt.Errorf("request body exceeds %d bytes", maxBodySize)
	}

	if s.r.re.Match(body) {
		out, err := s.expand(string(body))
		if err != nil {
			return err
		}
		body = []byte(out)
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return nil
}

// expand replaces every sentinel occurrence in in. An unknown name fails the
// whole request rather than letting the sentinel pass upstream unexpanded.
func (s *substitution) expand(in string) (string, error) {
	var b strings.Builder
	last := 0
	for _, m := range s.r.re.FindAllStringSubmatchIndex(in, -1) {
		name := ""
		if m[2] >= 0 {
			name = in[m[2]:m[3]]
		}
		cred, err := s.lookup(name)
		if err != nil {
			return "", err
		}
		b.WriteString(in[last:m[0]])
		b.WriteString(cred)
		last = m[1]
	}
	b.WriteString(in[last:])
	return b.String(), nil
}

func (s *substitution) lookup(name string) (string, error) {
	uri, ok := s.uris[name]
	if !ok {
		if name == "" {
			return "", fmt.Errorf("no default credential configured for %s", s.host)
		}
		return "", fmt.Errorf("credential %q not configured for host %s", name, s.host)
	}
	val, err := s.r.resolveURI(s.ctx, uri)
	if err != nil {
		return "", fmt.Errorf("resolving credential for %s: %w", s.host, err)
	}
	return val, nil
}

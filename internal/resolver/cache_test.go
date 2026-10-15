package resolver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/providers"
)

type totalCountProvider struct {
	resolved map[string]string
	calls    atomic.Int32
}

func (c *totalCountProvider) Resolve(_ context.Context, uri string) (string, error) {
	c.calls.Add(1)
	if v, ok := c.resolved[uri]; ok {
		return v, nil
	}
	return "", &providers.UnknownSchemeError{URI: uri}
}

func (c *totalCountProvider) Schemes() []string { return []string{"mock"} }

func newTotalCountResolver(hc config.HostConfig, resolved map[string]string) (*Resolver, *totalCountProvider) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"api.trello.com": hc}}
	cfg.SetDefaults()
	p := &totalCountProvider{resolved: resolved}
	reg := providers.NewRegistry()
	reg.Register(p)
	return New(cfg, reg), p
}

func resolveOnce(t *testing.T, r *Resolver) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/boards?key=CREDPROXY_TOKEN", nil)
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionCacheNeverExpires(t *testing.T) {
	r, p := newTotalCountResolver(trelloHost(), trelloCreds)
	r.SetCacheTTL(config.SessionCacheTTL)

	resolveOnce(t, r)
	// Age the entry far past any finite TTL.
	r.mu.Lock()
	for k, e := range r.cache {
		e.expires = time.Now().Add(-24 * time.Hour)
		r.cache[k] = e
	}
	r.mu.Unlock()
	resolveOnce(t, r)

	if got := p.calls.Load(); got != 1 {
		t.Errorf("provider calls = %d, want 1", got)
	}
}

func TestFiniteCacheExpires(t *testing.T) {
	r, p := newTotalCountResolver(trelloHost(), trelloCreds)

	resolveOnce(t, r)
	r.mu.Lock()
	for k, e := range r.cache {
		e.expires = time.Now().Add(-time.Second)
		r.cache[k] = e
	}
	r.mu.Unlock()
	resolveOnce(t, r)

	if got := p.calls.Load(); got != 2 {
		t.Errorf("provider calls = %d, want 2", got)
	}
}

func TestPrefetchResolvesDefaultAndNamedOnce(t *testing.T) {
	r, p := newTotalCountResolver(trelloHost(), trelloCreds)
	r.SetCacheTTL(config.SessionCacheTTL)

	if err := r.Prefetch(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := p.calls.Load(); got != 4 {
		t.Fatalf("prefetch provider calls = %d, want 4", got)
	}

	resolveOnce(t, r)
	if got := p.calls.Load(); got != 4 {
		t.Errorf("provider calls after request = %d, want 4 (served from cache)", got)
	}
}

func TestPrefetchFailsOnUnresolvableCredential(t *testing.T) {
	r, _ := newTotalCountResolver(trelloHost(), map[string]string{"mock://trello/key": "k"})

	if err := r.Prefetch(context.Background()); err == nil {
		t.Fatal("expected error for unresolvable named credential")
	}
}

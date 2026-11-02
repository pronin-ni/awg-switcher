package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebsiteScheduleAndPublicURLValidation(t *testing.T) {
	cfg := defaultWebsiteMonitorConfig()
	cfg.Schedule = WebsiteSchedule{Mode: "every", Minutes: 5, Timezone: "UTC"}
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	if got := nextWebsiteTime(now, cfg.Schedule); !got.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("every schedule=%s", got)
	}
	cfg.Schedule = WebsiteSchedule{Mode: "daily", Hour: 9, Minute: 30, Timezone: "Europe/Moscow"}
	got := nextWebsiteTime(now, cfg.Schedule)
	if got.In(mustLocation(t, "Europe/Moscow")).Hour() != 9 || got.In(mustLocation(t, "Europe/Moscow")).Minute() != 30 {
		t.Fatalf("daily schedule=%s", got)
	}
	cron, err := nextCronTime(now, "*/15 9-17 * * 1-5", "UTC")
	if err != nil || cron.Minute()%15 != 0 {
		t.Fatalf("cron next=%s err=%v", cron, err)
	}
	for _, raw := range []string{"http://example.org/", "https://user:pass@example.org/", "https://example.org:8443/"} {
		cfg.Websites = []Website{{ID: "x", Name: "x", URL: raw, Enabled: true, Required: true, Statuses: []int{200}}}
		if err := validateWebsiteConfig(cfg); err == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fd00::1", "100.64.0.1", "192.0.2.1"} {
		if ip := net.ParseIP(raw); isPublicIP(ip) {
			t.Errorf("accepted non-public IP %s", raw)
		}
	}
	if !isPublicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("rejected public IP")
	}
}

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestWebsiteProbeUsesSOCKSAndConfigured403Status(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	socks := newTestSocks(t, strings.TrimPrefix(server.URL, "https://"))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := &Controller{websiteResolver: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }, websiteTLSConfig: &tls.Config{RootCAs: roots}}
	settings := Settings{}
	settings.Proxy.ConnectTimeout = time.Second
	c.settings = settings
	p := &Profile{ID: "p", Name: "profile", session: &testSession{addr: socks.Addr()}, Healthy: true, enabled: true}
	w := Website{ID: "site", Name: "site", URL: "https://example.com/?access_token=not-to-persist", Statuses: []int{403}, Enabled: true, Required: true}
	probe := c.probeWebsite(context.Background(), p, w, 2*time.Second)
	if !probe.ok || probe.result.Status != 403 || probe.result.TLS != "verified" || probe.result.Outcome != "PASS" {
		t.Fatalf("expected configured 403 to pass with verified TLS: %+v", probe.result)
	}
	if strings.Contains(probe.result.URL, "access_token") || strings.Contains(probe.result.URL, "not-to-persist") {
		t.Fatalf("secret query leaked into history URL: %q", probe.result.URL)
	}
}

func TestWebsitePolicyFailureFailoverAndRecovery(t *testing.T) {
	var primaryStatus atomic.Int32
	primaryStatus.Store(http.StatusInternalServerError)
	primaryServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(primaryStatus.Load())) }))
	defer primaryServer.Close()
	backupServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backupServer.Close()
	primarySocks := newTestSocks(t, strings.TrimPrefix(primaryServer.URL, "https://"))
	backupSocks := newTestSocks(t, strings.TrimPrefix(backupServer.URL, "https://"))
	roots := x509.NewCertPool()
	roots.AddCert(primaryServer.Certificate())
	roots.AddCert(backupServer.Certificate())
	settings := Settings{}
	settings.Failover.Enabled = true
	settings.Failover.FailureThreshold = 2
	settings.Failover.RecoveryThreshold = 3
	settings.Health.RequiredSuccesses = 1
	primary := &Profile{ID: "primary", Name: "primary", Priority: 0, State: "HEALTHY", Healthy: true, enabled: true, RoutingEligible: true, WebsiteState: "PASSED", session: &testSession{addr: primarySocks.Addr()}}
	backup := &Profile{ID: "backup", Name: "backup", Priority: 1, State: "HEALTHY", Healthy: true, enabled: true, RoutingEligible: true, WebsiteState: "PASSED", session: &testSession{addr: backupSocks.Addr()}}
	c := &Controller{profiles: []*Profile{primary, backup}, settings: settings, websiteResolver: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }, websiteTLSConfig: &tls.Config{RootCAs: roots}}
	c.websiteConfig = WebsiteMonitorConfig{Enabled: true, Websites: []Website{{ID: "mandatory", Name: "required site", URL: "https://example.com/", Enabled: true, Required: true, Statuses: []int{200}}}, TimeoutSeconds: 2, FailureThreshold: 2, RecoveryThreshold: 3, Policy: "all_required", Schedule: WebsiteSchedule{Mode: "every", Minutes: 30, Timezone: "UTC"}}
	c.active.Store(primary)
	cycle := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.runWebsiteChecks(ctx); err != nil {
			t.Fatal(err)
		}
	}
	cycle()
	if primary.WebsiteState != "DEGRADED" || !primary.RoutingEligible || c.active.Load() != primary {
		t.Fatalf("single random website timeout should not block route: website=%s eligible=%v active=%v", primary.WebsiteState, primary.RoutingEligible, c.active.Load())
	}
	cycle()
	if primary.Healthy != true || primary.WebsiteState != "FAILED" || primary.RoutingEligible {
		t.Fatalf("website failure must not alter connectivity health but block routing: %+v", profileView(primary))
	}
	if c.active.Load() != backup {
		t.Fatalf("failed profile did not fail over to eligible backup: active=%v", c.active.Load())
	}
	primaryStatus.Store(http.StatusOK)
	cycle()
	if primary.WebsiteState != "PENDING" || primary.RoutingEligible || c.active.Load() != backup {
		t.Fatalf("first success prematurely recovered failed route: state=%s eligible=%v active=%v", primary.WebsiteState, primary.RoutingEligible, c.active.Load())
	}
	cycle()
	if primary.WebsiteState != "PENDING" || primary.RoutingEligible || c.active.Load() != backup {
		t.Fatalf("recovered before the configured third success: state=%s eligible=%v active=%v", primary.WebsiteState, primary.RoutingEligible, c.active.Load())
	}
	cycle()
	if primary.WebsiteState != "PASSED" || !primary.RoutingEligible || c.active.Load() != primary {
		t.Fatalf("website recovery did not restore route: state=%s eligible=%v active=%v", primary.WebsiteState, primary.RoutingEligible, c.active.Load())
	}
}

func TestWebsiteDNSFailureAndTimeoutAreNotConnectivityFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(100 * time.Millisecond); w.WriteHeader(200) }))
	defer server.Close()
	socks := newTestSocks(t, strings.TrimPrefix(server.URL, "https://"))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := &Controller{websiteResolver: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }, websiteTLSConfig: &tls.Config{RootCAs: roots}}
	p := &Profile{ID: "p", Name: "p", session: &testSession{addr: socks.Addr()}}
	w := Website{ID: "x", Name: "x", URL: "https://example.com/", Statuses: []int{200}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	got := c.probeWebsite(ctx, p, w, 5*time.Millisecond)
	if got.ok || got.result.Error != "timeout" {
		t.Fatalf("timeout not classified: %+v", got.result)
	}
	c.websiteResolver = func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("DNS lookup failed: synthetic DNS failure")
	}
	got = c.probeWebsite(context.Background(), p, w, time.Second)
	if got.ok || !strings.Contains(got.result.Error, "DNS lookup failed") {
		t.Fatalf("DNS failure not recorded: %+v", got.result)
	}
}

func TestWebsiteRedirectRejectsPrivateResolvedAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://internal.example/metadata", http.StatusFound)
	}))
	defer server.Close()
	socks := newTestSocks(t, strings.TrimPrefix(server.URL, "https://"))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := &Controller{
		websiteTLSConfig: &tls.Config{RootCAs: roots},
		websiteResolver: func(_ context.Context, host string) ([]net.IP, error) {
			if host == "example.com" {
				return []net.IP{net.ParseIP("8.8.8.8")}, nil
			}
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}
	p := &Profile{ID: "p", Name: "p", session: &testSession{addr: socks.Addr()}}
	result := c.probeWebsite(context.Background(), p, Website{ID: "s", Name: "redirect", URL: "https://example.com/", Statuses: []int{200}}, time.Second)
	if result.ok || !strings.Contains(result.result.Error, "non-public") {
		t.Fatalf("private redirect target wasn't rejected: %+v", result.result)
	}
}

func TestBlockedWebsiteProfileCannotBeManuallySelectedOrDialed(t *testing.T) {
	settings := Settings{}
	p := &Profile{ID: "blocked", Name: "blocked", Healthy: true, enabled: true, WebsiteState: "FAILED", RoutingEligible: false, socks: "127.0.0.1:1"}
	c := &Controller{profiles: []*Profile{p}, settings: settings, websiteConfig: WebsiteMonitorConfig{Enabled: true, Policy: "all_required", Websites: []Website{{ID: "required", Name: "required", URL: "https://example.com/", Enabled: true, Required: true}}}}
	if err := c.selectManual(p.ID, time.Minute); err == nil {
		t.Fatal("manual selection accepted website-blocked profile")
	}
	if _, err := c.dialProfile(context.Background(), p, "example.com:443"); err == nil || !strings.Contains(err.Error(), "website availability policy") {
		t.Fatalf("blocked route did not fail closed: %v", err)
	}
}

func TestWebsiteSettingsAndHistoryPersistence(t *testing.T) {
	dir := t.TempDir()
	c := &Controller{websiteDataDir: dir}
	cfg := defaultWebsiteMonitorConfig()
	cfg.Websites = []Website{{ID: "site", Name: "public", URL: "https://example.com/", Enabled: true, Required: true, Statuses: []int{200}}}
	if err := c.saveWebsiteMonitor(cfg); err != nil {
		t.Fatal(err)
	}
	state := struct {
		History []WebsiteCheckResult `json:"history"`
	}{History: []WebsiteCheckResult{{At: time.Now().UTC(), ProfileID: "p", WebsiteID: "site", Outcome: "PASS"}}}
	b, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(dir, "website-monitor-state.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.loadWebsiteHistory(); err != nil {
		t.Fatal(err)
	}
	loaded := &Controller{}
	if err := loaded.loadWebsiteMonitor(dir); err != nil {
		t.Fatal(err)
	}
	if got := loaded.websiteConfigSnapshot(); len(got.Websites) != 1 || got.TimeoutSeconds != cfg.TimeoutSeconds {
		t.Fatalf("settings did not persist: %+v", got)
	}
	if len(c.websiteHistory) != 1 || c.websiteHistory[0].Outcome != "PASS" {
		t.Fatalf("history did not persist: %+v", c.websiteHistory)
	}
}

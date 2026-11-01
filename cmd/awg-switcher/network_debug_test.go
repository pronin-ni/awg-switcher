package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNetworkDebugExpiresAndCanBeDisabled(t *testing.T) {
	c := &Controller{}
	expires := c.setNetworkDebug(true)
	if enabled, _ := c.networkDebugState(); !enabled || time.Until(expires) > 10*time.Minute {
		t.Fatal("debug mode did not enable with a bounded lifetime")
	}
	c.networkDebugMu.Lock()
	c.networkDebugUntil = time.Now().Add(-time.Second)
	c.networkDebugMu.Unlock()
	if enabled, _ := c.networkDebugState(); enabled {
		t.Fatal("expired debug mode remained enabled")
	}
	if until := c.setNetworkDebug(false); !until.IsZero() {
		t.Fatalf("disabled mode expiry=%s", until)
	}
}

func TestSupportBundleRedactsProfileAndDiagnosticSecrets(t *testing.T) {
	p := &Profile{ID: "safe-id", Name: "vpn", State: "HEALTHY", LastError: "https://user:password@example.test/?token=secret"}
	c := &Controller{profiles: []*Profile{p}, events: []ControllerEvent{{Kind: "profile_error", Message: "https://example.test/?token=secret"}}}
	trace := NetworkTrace{TraceID: "trace", Hostname: "example.test", DNS: "not_observable_inside_engine", Error: "operation timed out", Stages: map[string]TraceStage{}}
	c.networkTraces = []NetworkTrace{trace}
	encoded, err := json.Marshal(c.supportBundle())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", "token=secret", "LastError"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("support bundle leaked %q: %s", secret, encoded)
		}
	}
}

func TestWireproxyUsesTunnelDNSAndIPv4Preference(t *testing.T) {
	input := "[Interface]\nPrivateKey = PRIVATE\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = PUBLIC\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	got := string(wireproxyConfig([]byte(input)))
	if !strings.Contains(got, "DNS = 1.1.1.1\n[Peer]") || !strings.Contains(got, "[Resolve]\nResolveStrategy = ipv4") {
		t.Fatalf("runtime config did not configure tunnel DNS and IPv4: %q", got)
	}
	if strings.Contains(string(wireproxyConfig([]byte(strings.Replace(input, "Address =", "DNS = 9.9.9.9\nAddress =", 1)))), "DNS = 1.1.1.1") {
		t.Fatal("overrode profile-provided DNS")
	}
}

func TestTimeoutDefaultsKeepHealthchecksIndependent(t *testing.T) {
	settings := Settings{}
	defaults(&settings)
	if settings.Failover.CheckTimeout != 8*time.Second {
		t.Fatalf("health timeout=%s, want 8s", settings.Failover.CheckTimeout)
	}
	if settings.Failover.ManualCheckTimeout != 30*time.Second || settings.Proxy.ConnectTimeout != 30*time.Second {
		t.Fatalf("manual/connect deadlines=%s/%s, want 30s/30s", settings.Failover.ManualCheckTimeout, settings.Proxy.ConnectTimeout)
	}
	if settings.Failover.TLSHandshakeTimeout != 10*time.Second || settings.Failover.ResponseHeaderTimeout != 20*time.Second {
		t.Fatalf("TLS/header deadlines=%s/%s, want 10s/20s", settings.Failover.TLSHandshakeTimeout, settings.Failover.ResponseHeaderTimeout)
	}
}

func TestSOCKSErrorRetainsTimeoutAndDNSClassification(t *testing.T) {
	timeout := &net.DNSError{Err: "i/o timeout", Name: "example.test", IsTimeout: true}
	if got := classifyHealthError(&SOCKSError{Stage: "socks5_connect", Err: timeout}); got != "dns_timeout" {
		t.Fatalf("DNS timeout classification=%q", got)
	}
	if got := classifyHealthError(&SOCKSError{Stage: "socks5_negotiation", Err: context.DeadlineExceeded}); got != "timeout" {
		t.Fatalf("negotiation deadline classification=%q", got)
	}
	var wrapped *SOCKSError
	if !errors.As(fmt.Errorf("diagnostic: %w", &SOCKSError{Stage: "socks5_connect", Err: timeout}), &wrapped) {
		t.Fatal("structured SOCKS error lost its wrapped cause")
	}
}

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const validWG = `[Interface]
PrivateKey = <SYNTHETIC-TEST-NOT-SECRET>
Address = 172.16.0.2, 2606:4700:110:8a42:9e2:195e:b8c0:c75b
MTU = 1280
Jc = 4
S3 = 12
[Peer]
PublicKey = peer-key
Endpoint = vpn.example.test:51820
AllowedIPs = 0.0.0.0/0, ::/0
`

func TestNormalizeDualStackBareAddresses(t *testing.T) {
	b, err := normalizeWG([]byte(validWG))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "172.16.0.2/32") || !strings.Contains(s, "2606:4700:110:8a42:9e2:195e:b8c0:c75b/128") {
		t.Fatalf("address normalization failed: %s", s)
	}
	if !strings.Contains(s, "S3 = 12") || !strings.Contains(s, "MTU = 1280") {
		t.Fatal("AWG/WARP fields lost")
	}
}

func TestNormalizeRejectsUnknownFields(t *testing.T) {
	_, err := normalizeWG([]byte(validWG + "MysteryCipher = secret\n"))
	if err == nil || !strings.Contains(err.Error(), "unsupported setting") {
		t.Fatalf("wanted explicit rejection, got %v", err)
	}
}

func TestNormalizeRequiresPeerAndKey(t *testing.T) {
	_, err := normalizeWG([]byte("[Interface]\nAddress = 10.0.0.2\n"))
	if err == nil {
		t.Fatal("accepted incomplete profile")
	}
}

func TestNormalizeRejectsInvalidWireGuardRanges(t *testing.T) {
	for _, test := range []struct {
		field   string
		section string
	}{
		{"PersistentKeepalive = 35-25", "peer"},
		{"ContentPaddingAddition = 10-", "interface"},
		{"RekeyAfterTime = 4-4294967296", "interface"},
		{"KeepaliveTimeout = not-a-range", "interface"},
	} {
		config := validWG + "\n" + test.field + "\n"
		if test.section == "interface" {
			config = strings.Replace(validWG, "[Peer]", test.field+"\n[Peer]", 1)
		}
		_, err := normalizeWG([]byte(config))
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%q was not rejected safely: %v", test.field, err)
		}
	}
}

func TestNormalizeRejectsKnownSettingsInWrongSection(t *testing.T) {
	_, err := normalizeWG([]byte(validWG + "ContentPaddingAddition = 10-100\n"))
	if err == nil || !strings.Contains(err.Error(), "not valid in [peer]") {
		t.Fatalf("AWG 3.x interface setting in [Peer] was not rejected: %v", err)
	}
}

func TestAWG3ValuesAndLargeCPSSurviveRuntimeConfig(t *testing.T) {
	i1 := "<b 0x" + strings.Repeat("ab", 625) + ">"
	config := `[Interface]
PrivateKey = <SYNTHETIC-TEST-NOT-SECRET>
Address = 172.16.0.2, 2606:4700:110:8a42::2
MTU = 1280
Jc = 12
S1 = 0
S2 = 0
S3 = 0
S4 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = ` + i1 + `
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
[Peer]
PublicKey = synthetic-public-key
Endpoint = vpn.example.test:2408
PersistentKeepalive = 25-35
AllowedIPs = 0.0.0.0/0
`
	normalized, err := normalizeWG([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfig := wireproxyConfig(normalized)
	for _, want := range []string{
		"MTU = 1280", "I1 = " + i1,
		"ContentPaddingAddition = 10-100", "RekeyAfterTime = 100-120",
		"RekeyTimeout = 3-7", "RejectAfterTime = 150-180",
		"KeepaliveTimeout = 5-15", "MaxHandshakeAttempts = 15-20",
		"PersistentKeepalive = 25-35", "AllowedIPs = 0.0.0.0/0",
		"ResolveStrategy = ipv4",
	} {
		if !strings.Contains(string(runtimeConfig), want) {
			t.Errorf("runtime config lost parameter %q", want)
		}
	}
	if !strings.Contains(string(runtimeConfig), "172.16.0.2/32") || !strings.Contains(string(runtimeConfig), "/128") {
		t.Fatal("dual-stack Address prefixes were not preserved in runtime config")
	}
}

func TestAWG30CPSPayloadSurvivesRuntimeConfig(t *testing.T) {
	i1 := "<b 0x" + strings.Repeat("de", 340) + ">"
	config := strings.Replace(validWG, "[Peer]", "I1 = "+i1+"\n[Peer]", 1)
	normalized, err := normalizeWG([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wireproxyConfig(normalized)), "I1 = "+i1) {
		t.Fatal("AWG 3.0 CPS I1 was changed by normalization/runtime configuration")
	}
}

func TestProcessEngineTransmitsAWG3RangesAndCPS(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "fake-engine")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	i1 := "<b 0x" + strings.Repeat("cd", 625) + ">"
	configText := strings.ReplaceAll(validWG, "Jc = 4", "Jc = 12")
	configText = strings.ReplaceAll(configText, "S3 = 12", "S1 = 0\nS2 = 0\nS3 = 0\nS4 = 0")
	configText = strings.ReplaceAll(configText, "AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/0")
	interfaceParams := "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nI1 = " + i1 + "\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\nRekeyTimeout = 3-7\nRejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\n"
	configText = strings.Replace(configText, "[Peer]", interfaceParams+"[Peer]", 1)
	configText = strings.Replace(configText, "Endpoint = vpn.example.test:51820", "Endpoint = vpn.example.test:51820\nPersistentKeepalive = 25-35", 1)
	config := []byte(configText)
	normalized, err := normalizeWG(config)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(dir, "runtime")
	engine := ProcessEngine{Binary: binary, RuntimeDir: runtimeDir}
	session, err := engine.Start(context.Background(), normalized, "127.0.0.1:21000", 17)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := os.ReadFile(filepath.Join(runtimeDir, "profile-00000011.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{i1, "ContentPaddingAddition = 10-100", "PersistentKeepalive = 25-35", "MaxHandshakeAttempts = 15-20"} {
		if !strings.Contains(string(runtime), want) {
			t.Errorf("engine runtime config lost %q", want)
		}
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := session.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsDurationStrings(t *testing.T) {
	var s Settings
	if err := yaml.Unmarshal([]byte("failover:\n  check_interval: 15s\n  check_timeout: 8s\n"), &s); err != nil {
		t.Fatalf("duration strings in settings.yaml must parse: %v", err)
	}
	if s.Failover.CheckInterval != 15*time.Second || s.Failover.CheckTimeout != 8*time.Second {
		t.Fatalf("unexpected durations: %#v", s.Failover)
	}
}

func TestHealthStatusDoesNotTreatApplicationErrorsAsVPNFailures(t *testing.T) {
	for _, status := range []int{200, 403, 404, 429, 500, 503} {
		if !healthHTTPStatusReachable(status) {
			t.Errorf("HTTP %d should prove transport reachability", status)
		}
	}
	for _, status := range []int{0, 600, 999} {
		if healthHTTPStatusReachable(status) {
			t.Errorf("invalid HTTP status %d considered reachable", status)
		}
	}
}

func TestRetryDelayExponentialAndRateLimited(t *testing.T) {
	now := time.Now()
	history := []time.Time(nil)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	for i, d := range want {
		got, next := retryDelay(now.Add(time.Duration(i)*time.Second), history)
		if got != d {
			t.Fatalf("retry %d delay=%s want=%s", i+1, got, d)
		}
		history = next
	}
	got, history := retryDelay(now.Add(6*time.Second), history)
	if got != 5*time.Minute {
		t.Fatalf("restart storm delay=%s want 5m", got)
	}
	got, _ = retryDelay(now.Add(20*time.Minute), history)
	if got != time.Second {
		t.Fatalf("expired restart history delay=%s want 1s", got)
	}
}

func TestHealthyProbeDoesNotResetRestartRateLimit(t *testing.T) {
	s := Settings{}
	s.Failover.FailureThreshold = 2
	s.Failover.RecoveryThreshold = 2
	history := []time.Time{time.Now().Add(-4 * time.Minute), time.Now().Add(-3 * time.Minute), time.Now().Add(-2 * time.Minute), time.Now().Add(-time.Minute), time.Now()}
	p := &Profile{Name: "primary", State: "CONNECTING", restartTimes: history}
	c := &Controller{settings: s}
	c.recordHealth(p, healthResult{Healthy: true, TransportOK: true})
	if len(p.restartTimes) != len(history) {
		t.Fatalf("successful health probe reset restart history: got %d entries, want %d", len(p.restartTimes), len(history))
	}
}

func TestProcessEngineStopsAndRemovesPrivateRuntimeConfig(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "fake-engine")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	engine := ProcessEngine{Binary: binary, RuntimeDir: filepath.Join(dir, "runtime")}
	session, err := engine.Start(context.Background(), []byte(validWG), "127.0.0.1:21000", 0)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "runtime", "profile-00000000.conf")
	info, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("runtime config permissions=%04o", info.Mode().Perm())
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := session.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.Done():
	default:
		t.Fatal("engine process was not reaped")
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("runtime config was not removed: %v", err)
	}
}

func TestProxyNeverFallsBackDirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	settings := Settings{}
	settings.Failover.CheckTimeout = 150 * time.Millisecond
	c := &Controller{settings: settings}
	p := &Profile{Name: "broken", State: "HEALTHY", Healthy: true, socks: "127.0.0.1:1"}
	p.transport = &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.socksDial(ctx, p, address)
	}}
	c.active.Store(p)
	proxy := httptest.NewServer(c.proxyHandler())
	defer proxy.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL, nil)
	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected fail-closed 502, got %d", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("DIRECT fallback reached target %d times", hits.Load())
	}
}

func TestSelectProfileUsesPriorityAndAtomicActive(t *testing.T) {
	c := &Controller{settings: Settings{Failover: struct {
		Enabled               bool          `yaml:"enabled"`
		CheckInterval         time.Duration `yaml:"check_interval"`
		CheckTimeout          time.Duration `yaml:"check_timeout"`
		ManualCheckTimeout    time.Duration `yaml:"manual_check_timeout"`
		TLSHandshakeTimeout   time.Duration `yaml:"tls_handshake_timeout"`
		ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout"`
		FailureThreshold      int           `yaml:"failure_threshold"`
		RecoveryThreshold     int           `yaml:"recovery_threshold"`
		RecoveryInterval      time.Duration `yaml:"recovery_interval"`
		SwitchCooldown        time.Duration `yaml:"switch_cooldown"`
	}{Enabled: true, SwitchCooldown: time.Second}}}
	primary := &Profile{Name: "primary", Priority: 0, Healthy: true, enabled: true}
	backup := &Profile{Name: "backup", Priority: 1, Healthy: true, enabled: true}
	c.profiles = []*Profile{primary, backup}
	c.selectProfile()
	if got := c.active.Load(); got != primary {
		t.Fatalf("active profile=%v, want primary", got)
	}
	primary.Healthy = false
	c.selectProfile()
	if got := c.active.Load(); got != backup {
		t.Fatalf("active profile=%v, want backup", got)
	}
}

func TestSnapshotActiveIsStableProfileIDNotDisplayName(t *testing.T) {
	p := &Profile{ID: "opaque-profile-id", Name: "Readable name", Priority: 1, Healthy: true, enabled: true}
	c := &Controller{profiles: []*Profile{p}}
	c.active.Store(p)
	if got := c.snapshot().Active; got != p.ID {
		t.Fatalf("snapshot active=%q; want stable id %q", got, p.ID)
	}
}

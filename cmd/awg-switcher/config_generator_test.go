package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type generatorRoundTripFunc func(*http.Request) (*http.Response, error)

func (f generatorRoundTripFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestNormalizeGeneratorURLRestrictsHTTPAndRemoteSchemes(t *testing.T) {
	tests := []struct {
		input, want string
		fail        bool
	}{
		{"http://awg-config-gen:3000", "http://awg-config-gen:3000", false},
		{"http://example.com", "", true},
		{"http://127.0.0.1:3000", "", true},
		{"https://warp-gen.example.org", "https://warp-gen.example.org", false},
		{"https://warp-gen.example.org/path", "", true},
		{"https://user:pass@warp-gen.example.org", "", true},
		{"https://127.0.0.1", "", true},
		{"https://host.local", "", true},
	}
	for _, tt := range tests {
		got, err := normalizeGeneratorURL(tt.input)
		if tt.fail && err == nil {
			t.Errorf("accepted unsafe URL %q", tt.input)
			continue
		}
		if !tt.fail && (err != nil || got != tt.want) {
			t.Errorf("normalize(%q)=(%q,%v), want %q", tt.input, got, err, tt.want)
		}
	}
}

func TestGeneratorDialIPBlocksPrivateTargets(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.2", "169.254.169.254", "100.64.0.4"} {
		if isAllowedGeneratorIP(net.ParseIP(ip), false) {
			t.Errorf("allowed blocked IP %s", ip)
		}
	}
	if !isAllowedGeneratorIP(net.ParseIP("100.64.0.4"), true) {
		t.Fatal("expected Tailscale CGNAT destination to be allowed for .ts.net")
	}
	if !isAllowedGeneratorIP(net.ParseIP("1.1.1.1"), false) {
		t.Fatal("rejected public IP")
	}
}

func TestGeneratedConfigMustBeValidatedIPv4FullTunnel(t *testing.T) {
	valid := strings.Replace(validWG, ", ::/0", "", 1)
	raw, normalized, err := decodeGeneratedConfig(base64.StdEncoding.EncodeToString([]byte(valid)))
	if err != nil || len(raw) == 0 || len(normalized) == 0 {
		t.Fatalf("valid generated config rejected: %v", err)
	}
	for _, invalid := range []string{
		validWG,
		strings.Replace(valid, "0.0.0.0/0", "10.0.0.0/8", 1),
		strings.Replace(valid, "0.0.0.0/0", "0.0.0.0/0, 192.168.0.0/16", 1),
	} {
		if _, _, err := decodeGeneratedConfig(base64.StdEncoding.EncodeToString([]byte(invalid))); err == nil {
			t.Errorf("accepted invalid route config %q", invalid)
		}
	}
	if _, _, err := decodeGeneratedConfig("not base64!"); err == nil {
		t.Fatal("accepted malformed base64")
	}
}

func TestGeneratorRetryAfterParsing(t *testing.T) {
	now := time.Now().UTC()
	if got := parseRetryAfter("17", now); got != 17*time.Second {
		t.Fatalf("integer Retry-After=%s", got)
	}
	if got := parseRetryAfter("99999", now); got != time.Hour {
		t.Fatalf("bounded Retry-After=%s", got)
	}
	if got := parseRetryAfter("bad", now); got != time.Minute {
		t.Fatalf("fallback Retry-After=%s", got)
	}
}

func TestGeneratorSettingsProtectBearerTokenOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := &webServer{dataDir: dir}
	if err := s.saveGeneratorSettings(configGeneratorSettings{URL: defaultGeneratorURL, BearerToken: "synthetic-secret-token"}); err != nil {
		t.Fatal(err)
	}
	path := generatorSettingsPath(dir)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("settings file mode/info: %v %v", info, err)
	}
	cfg, err := s.generatorSettings()
	if err != nil || cfg.BearerToken != "synthetic-secret-token" {
		t.Fatalf("settings not restored: %+v %v", cfg, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "profiles")); !os.IsNotExist(err) {
		t.Fatalf("unexpected profile storage: %v", err)
	}
}

func TestGeneratedProfilesAreAddedDisabledWithoutChangingActiveRoute(t *testing.T) {
	primary := &Profile{ID: "main", Name: "existing", Priority: 0, State: "HEALTHY", Healthy: true, enabled: true}
	c := &Controller{profiles: []*Profile{primary}, maxEngines: 64}
	c.active.Store(primary)
	p, err := c.addDisabledRuntimeProfile("generated-id", "WARP AWG 2.0 1", []byte(validWG), "/data/profiles/generated-id.conf")
	if err != nil {
		t.Fatal(err)
	}
	if p.enabled || p.State != "DISABLED" {
		t.Fatalf("new profile state=%s enabled=%t", p.State, p.enabled)
	}
	if c.active.Load() != primary {
		t.Fatal("adding generated profile changed active route")
	}
}

func TestGeneratorClientPostsBoundedHostnameModeAndDecodesAPIResponse(t *testing.T) {
	fullTunnel := strings.Replace(validWG, ", ::/0", "", 1)
	encoded := base64.StdEncoding.EncodeToString([]byte(fullTunnel))
	client := generatorRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/api/warp" || req.Method != http.MethodPost {
			t.Fatalf("unexpected generator request %s %s", req.Method, req.URL.Path)
		}
		if req.Header.Get("Authorization") != "Bearer test-auth" {
			t.Fatal("backend did not attach configured Bearer token")
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["mode"] != "awg31" || body["count"] != float64(2) || body["endpointMode"] != "hostname" || body["ipv6"] != false || body["cps"] != "static" {
			t.Fatalf("unsafe or unexpected generation request: %+v", body)
		}
		payload, _ := json.Marshal(map[string]any{"success": true, "count": 1, "mode": "awg31", "configs": []any{map[string]string{"content": encoded}}})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(payload)))}, nil
	})
	cfg := configGeneratorSettings{URL: "https://gen.example.org", BearerToken: "test-auth"}
	result, err := requestWarpConfigsUsing(context.Background(), cfg, "awg31", 2, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Configs) != 1 || result.Mode != "awg31" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, _, err = decodeGeneratedConfig(result.Configs[0].Content); err != nil {
		t.Fatalf("API returned config did not decode: %v", err)
	}
}

func TestGeneratorClientPreserves429RetryAfterWithoutRetrying(t *testing.T) {
	calls := 0
	client := generatorRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"23"}}, Body: io.NopCloser(strings.NewReader(`{"success":false}`))}, nil
	})
	_, err := requestWarpConfigsUsing(context.Background(), configGeneratorSettings{URL: "https://gen.example.org"}, "awg2", 1, client)
	apiErr, ok := err.(*configGeneratorAPIError)
	if !ok || apiErr.StatusCode != 429 || apiErr.RetryAfter != 23*time.Second {
		t.Fatalf("429 response not preserved: %v", err)
	}
	if calls != 1 {
		t.Fatalf("generator request retried %d times", calls)
	}
}

func TestGeneratorSettingsHTTPSRequiresBearerAndRejectsSSRFHosts(t *testing.T) {
	s := &webServer{dataDir: t.TempDir()}
	if err := s.saveGeneratorSettings(configGeneratorSettings{URL: "https://gen.example.org"}); err == nil {
		t.Fatal("remote HTTPS allowed without auth")
	}
	for _, raw := range []string{"http://169.254.169.254", "http://localhost:3000", "https://localhost", "https://10.0.0.1"} {
		if _, err := normalizeGeneratorURL(raw); err == nil {
			t.Errorf("accepted SSRF URL %q", raw)
		}
	}
}

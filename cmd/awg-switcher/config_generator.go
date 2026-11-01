package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGeneratorURL      = "http://awg-config-gen:3000"
	maxGeneratorBody         = 5 << 20
	generatorTimeout         = 65 * time.Second
	generatorWorkflowTimeout = 3 * time.Minute
)

type configGeneratorSettings struct {
	URL         string `json:"url"`
	BearerToken string `json:"bearer_token,omitempty"`
}

type configGeneratorAPIError struct {
	StatusCode int
	RetryAfter time.Duration
}

type generatorHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func (e *configGeneratorAPIError) Error() string {
	if e.StatusCode == http.StatusTooManyRequests {
		return "configuration generator rate limit reached"
	}
	return fmt.Sprintf("configuration generator returned HTTP %d", e.StatusCode)
}

type generatedConfigResponse struct {
	Success bool   `json:"success"`
	Count   int    `json:"count"`
	Mode    string `json:"mode"`
	Warning any    `json:"warning"`
	Configs []struct {
		Content string `json:"content"`
	} `json:"configs"`
}

func normalizeGeneratorURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 2048 {
		return "", errors.New("generator URL is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("enter a generator base URL without credentials, path, query or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if u.Scheme == "http" {
		port := u.Port()
		if host != "awg-config-gen" || (port != "" && port != "3000") {
			return "", errors.New("unencrypted HTTP is allowed only for the local awg-config-gen:3000 service")
		}
		return "http://awg-config-gen:3000", nil
	}
	if u.Scheme != "https" || net.ParseIP(host) != nil || strings.Contains(host, "_") {
		return "", errors.New("remote generators must use an HTTPS DNS hostname")
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".lan", ".test"} {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return "", errors.New("generator hostname is not allowed")
		}
	}
	if u.Port() == "" {
		return "https://" + u.Hostname(), nil
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("invalid generator URL port")
	}
	return "https://" + net.JoinHostPort(u.Hostname(), u.Port()), nil
}

func generatorSettingsPath(dir string) string { return filepath.Join(dir, "config-generator.json") }

func (s *webServer) generatorSettings() (configGeneratorSettings, error) {
	s.configGenMu.Lock()
	defer s.configGenMu.Unlock()
	if s.configGenLoaded {
		return s.configGen, nil
	}
	cfg := configGeneratorSettings{URL: defaultGeneratorURL}
	path := generatorSettingsPath(s.dataDir)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return configGeneratorSettings{}, errors.New("generator settings permissions are unsafe")
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil || json.Unmarshal(b, &cfg) != nil {
			return configGeneratorSettings{}, errors.New("generator settings are invalid")
		}
	} else if !os.IsNotExist(err) {
		return configGeneratorSettings{}, errors.New("generator settings are unavailable")
	}
	base, err := normalizeGeneratorURL(cfg.URL)
	if err != nil {
		return configGeneratorSettings{}, errors.New("saved generator URL is invalid; update it in the Web UI")
	}
	cfg.URL = base
	s.configGen = cfg
	s.configGenLoaded = true
	return cfg, nil
}

func (s *webServer) saveGeneratorSettings(cfg configGeneratorSettings) error {
	base, err := normalizeGeneratorURL(cfg.URL)
	if err != nil {
		return err
	}
	if strings.HasPrefix(base, "https://") && strings.TrimSpace(cfg.BearerToken) == "" {
		return errors.New("a bearer token is required for a remote HTTPS generator")
	}
	if len(cfg.BearerToken) > 4096 || strings.ContainsAny(cfg.BearerToken, "\r\n") {
		return errors.New("invalid generator bearer token")
	}
	cfg.URL = base
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(s.dataDir, 0700); err != nil {
		return errors.New("generator settings storage unavailable")
	}
	path := generatorSettingsPath(s.dataDir)
	if info, statErr := os.Lstat(path); statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("generator settings path is unsafe")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return errors.New("generator settings storage unavailable")
	}
	tmp, err := os.CreateTemp(s.dataDir, ".config-generator-*.tmp")
	if err != nil {
		return errors.New("generator settings storage unavailable")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil || os.Rename(tmpPath, path) != nil {
		return errors.New("generator settings could not be saved")
	}
	s.configGenMu.Lock()
	s.configGen, s.configGenLoaded = cfg, true
	s.configGenMu.Unlock()
	return nil
}

func generatorHTTPClient(baseURL string) *http.Client {
	parsed, _ := url.Parse(baseURL)
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "3000"
		}
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			requestHost, requestPort, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(requestHost, hostname) || requestPort != port {
				return nil, errors.New("generator dial target rejected")
			}
			if hostname == "awg-config-gen" && parsed.Scheme == "http" {
				return dialer.DialContext(ctx, network, net.JoinHostPort(hostname, port))
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
			if err != nil {
				return nil, errors.New("generator hostname resolution failed")
			}
			allowCGNAT := strings.HasSuffix(hostname, ".ts.net")
			var lastErr error
			for _, candidate := range ips {
				ip := candidate.IP
				if !isAllowedGeneratorIP(ip, allowCGNAT) {
					continue
				}
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			if lastErr != nil {
				return nil, errors.New("generator connection failed")
			}
			return nil, errors.New("generator address resolved to a blocked network")
		},
		TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: generatorTimeout,
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: transport, Timeout: generatorTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func isAllowedGeneratorIP(ip net.IP, allowCGNAT bool) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if cgnat := net.ParseIP("100.64.0.1"); cgnat != nil && ip.To4() != nil {
		_, block, _ := net.ParseCIDR("100.64.0.0/10")
		if block.Contains(ip) {
			return allowCGNAT
		}
	}
	return ip.IsGlobalUnicast()
}

func generatorRequest(ctx context.Context, cfg configGeneratorSettings, method, endpoint string, body []byte) (*http.Response, error) {
	return generatorRequestUsing(ctx, cfg, method, endpoint, body, generatorHTTPClient(cfg.URL))
}

func generatorRequestUsing(ctx context.Context, cfg configGeneratorSettings, method, endpoint string, body []byte, client generatorHTTPDoer) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(cfg.URL, "/")+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create generator request")
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("generator is unreachable or timed out")
	}
	return resp, nil
}

func checkGeneratorConnection(ctx context.Context, cfg configGeneratorSettings) error {
	return checkGeneratorConnectionUsing(ctx, cfg, generatorHTTPClient(cfg.URL))
}

func checkGeneratorConnectionUsing(ctx context.Context, cfg configGeneratorSettings, client generatorHTTPDoer) error {
	resp, err := generatorRequestUsing(ctx, cfg, http.MethodGet, "/api/status", nil, client)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("generator status check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func requestWarpConfigs(ctx context.Context, cfg configGeneratorSettings, mode string, count int) (generatedConfigResponse, error) {
	return requestWarpConfigsUsing(ctx, cfg, mode, count, generatorHTTPClient(cfg.URL))
}

func requestWarpConfigsUsing(ctx context.Context, cfg configGeneratorSettings, mode string, count int, client generatorHTTPDoer) (generatedConfigResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"mode": mode, "count": count, "endpointMode": "hostname", "ipv6": false, "cps": "static",
	})
	resp, err := generatorRequestUsing(ctx, cfg, http.MethodPost, "/api/warp", body, client)
	if err != nil {
		return generatedConfigResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retry := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return generatedConfigResponse{}, &configGeneratorAPIError{StatusCode: resp.StatusCode, RetryAfter: retry}
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxGeneratorBody+1))
	if err != nil || len(bodyBytes) > maxGeneratorBody {
		return generatedConfigResponse{}, errors.New("generator response exceeds size limit")
	}
	var result generatedConfigResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return generatedConfigResponse{}, errors.New("generator returned invalid JSON")
	}
	if !result.Success || len(result.Configs) == 0 || len(result.Configs) > count {
		return generatedConfigResponse{}, errors.New("generator did not return usable configurations")
	}
	return result, nil
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds > 0 {
		if seconds > 3600 {
			seconds = 3600
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		d := at.Sub(now)
		if d > time.Hour {
			return time.Hour
		}
		return d
	}
	return time.Minute
}

func decodeGeneratedConfig(encoded string) ([]byte, []byte, error) {
	if len(encoded) == 0 || len(encoded) > maxProfileBytes*2 {
		return nil, nil, errors.New("generated configuration size is invalid")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxProfileBytes {
		return nil, nil, errors.New("generator returned invalid base64 configuration")
	}
	normalized, err := normalizeWG(raw)
	if err != nil {
		return nil, nil, errors.New("generated configuration failed AWG validation")
	}
	if err = validateGeneratedFullTunnel(normalized); err != nil {
		return nil, nil, err
	}
	return raw, normalized, nil
}

func validateGeneratedFullTunnel(config []byte) error {
	section := ""
	allowedCount := 0
	peerCount := 0
	for _, line := range strings.Split(string(config), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			section = strings.ToLower(trim[1 : len(trim)-1])
			if section == "peer" {
				peerCount++
			}
			continue
		}
		if section != "peer" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		key, value, ok := strings.Cut(trim, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "AllowedIPs") {
			continue
		}
		for _, route := range strings.Split(value, ",") {
			allowedCount++
			if strings.TrimSpace(route) != "0.0.0.0/0" {
				return errors.New("generated config is not full-tunnel IPv4")
			}
		}
	}
	if peerCount != 1 || allowedCount != 1 {
		return errors.New("generated config must contain only AllowedIPs = 0.0.0.0/0")
	}
	return nil
}

func storeImportedProfile(dataDir string, normalized []byte) (string, string, error) {
	profileDir := filepath.Join(dataDir, "profiles")
	if err := os.MkdirAll(profileDir, 0700); err != nil {
		return "", "", err
	}
	info, err := os.Lstat(profileDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("profile directory is unsafe")
	}
	if err := os.Chmod(profileDir, 0700); err != nil {
		return "", "", err
	}
	token, err := randomToken(18)
	if err != nil {
		return "", "", err
	}
	id := strings.ToLower(strings.TrimRight(base64.RawURLEncoding.EncodeToString([]byte(token)), "="))
	path := filepath.Join(profileDir, id+".conf")
	tmp, err := os.CreateTemp(profileDir, ".import-*.tmp")
	if err != nil {
		return "", "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(normalized)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", "", err
	}
	if err = os.Link(tmpName, path); err != nil {
		return "", "", err
	}
	return id, path, nil
}

func (c *Controller) testGeneratedProfile(ctx context.Context, source *Profile) (map[string]any, string) {
	if c.engine == nil {
		return nil, "engine_unavailable"
	}
	temp := &Profile{ID: source.ID + "-probe", Name: "temporary WARP verification", State: "CONNECTING", config: append([]byte(nil), source.config...), enabled: true}
	c.prepareProfile(temp)
	session, err := c.engine.Start(ctx, temp.config, temp.socks, temp.slot)
	if err != nil {
		return map[string]any{"error_type": "engine_start_failed"}, "engine_start_failed"
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		_ = session.Stop(stopCtx)
		cancel()
	}()
	temp.mu.Lock()
	temp.session = session
	temp.socks = session.SOCKSAddr()
	temp.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return map[string]any{"error_type": "timeout"}, "timeout"
		}
		select {
		case <-session.Done():
			return map[string]any{"error_type": "engine_exited"}, "engine_exited"
		default:
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err = c.socksHandshake(handshakeCtx, session.SOCKSAddr())
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return map[string]any{"error_type": "socks_listener_unavailable"}, "socks_listener_unavailable"
		}
		time.Sleep(100 * time.Millisecond)
	}
	result := c.checkURL(ctx, temp, "https://api.ipify.org")
	status, _ := result["http_status"].(int)
	stages, _ := result["stages"].(map[string]TraceStage)
	_, socksOK := stages["socks5_connect"]
	tlsStage, tlsOK := stages["tls_handshake"]
	failureStage, _ := result["failure_stage"].(string)
	socksStage := stages["socks5_connect"]
	if failureStage != "" || !socksOK || socksStage.Status != "success" || !tlsOK || tlsStage.Status != "success" || status < 200 || status >= 300 {
		reason, _ := result["error_type"].(string)
		if reason == "" {
			reason = "https_probe_failed"
		}
		return result, reason
	}
	return result, ""
}

func (s *webServer) configGeneratorSettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		cfg, err := s.generatorSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"url": cfg.URL, "token_configured": cfg.BearerToken != "", "endpoint_mode": "hostname", "lab_auto_available": false})
	case http.MethodPost:
		var req struct {
			URL         string  `json:"url"`
			BearerToken *string `json:"bearer_token"`
			ClearToken  bool    `json:"clear_token"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req) != nil {
			http.Error(w, "invalid generator settings", http.StatusBadRequest)
			return
		}
		current, loadErr := s.generatorSettings()
		if loadErr != nil {
			http.Error(w, loadErr.Error(), http.StatusInternalServerError)
			return
		}
		cfg := configGeneratorSettings{URL: req.URL, BearerToken: current.BearerToken}
		if req.BearerToken != nil {
			cfg.BearerToken = *req.BearerToken
		}
		if req.ClearToken {
			cfg.BearerToken = ""
		}
		if err := s.saveGeneratorSettings(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"saved": true, "url": cfg.URL, "token_configured": cfg.BearerToken != "", "endpoint_mode": "hostname", "lab_auto_available": false})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *webServer) testConfigGeneratorHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := s.generatorSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err = checkGeneratorConnection(ctx, cfg); err != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": "Generator API is reachable. No WARP registration was performed."})
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *webServer) generateWarpProfilesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Mode  string `json:"mode"`
		Count int    `json:"count"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		http.Error(w, "invalid generation request", http.StatusBadRequest)
		return
	}
	mode := map[string]string{"awg2": "awg2", "2.0": "awg2", "awg3": "awg3", "3.0": "awg3", "awg31": "awg31", "3.1": "awg31"}[strings.ToLower(strings.TrimSpace(req.Mode))]
	if mode == "" || req.Count < 1 || req.Count > 3 {
		http.Error(w, "choose AWG 2.0, 3.0 or 3.1 and a count from 1 to 3", http.StatusBadRequest)
		return
	}
	cfg, err := s.generatorSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !s.configGenRun.TryLock() {
		w.Header().Set("Retry-After", "10")
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "A WARP generation is already in progress.", "retry_after_seconds": 10})
		return
	}
	defer s.configGenRun.Unlock()
	now := time.Now()
	s.configGenMu.Lock()
	cutoff := now.Add(-time.Minute)
	kept := s.configGenStarts[:0]
	for _, at := range s.configGenStarts {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	s.configGenStarts = kept
	if len(kept) >= 3 {
		retry := time.Until(kept[0].Add(time.Minute))
		seconds := int(retry.Seconds()) + 1
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		s.configGenMu.Unlock()
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "Local generation limit reached; try again later.", "retry_after_seconds": seconds})
		return
	}
	s.configGenStarts = append(kept, now)
	s.configGenMu.Unlock()

	workflowCtx, cancelWorkflow := context.WithTimeout(r.Context(), generatorWorkflowTimeout)
	defer cancelWorkflow()
	generationCtx, cancelGeneration := context.WithTimeout(workflowCtx, generatorTimeout)
	defer cancelGeneration()
	if err := checkGeneratorConnection(generationCtx, cfg); err != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{"success": false, "message": err.Error()})
		return
	}
	generation, err := requestWarpConfigs(generationCtx, cfg, mode, req.Count)
	if err != nil {
		var apiErr *configGeneratorAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests {
			seconds := int(apiErr.RetryAfter.Seconds())
			if seconds < 1 {
				seconds = 60
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			writeJSONStatus(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "Cloudflare or the generator rate limit was reached; no automatic retry was made.", "retry_after_seconds": seconds})
			return
		}
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{"success": false, "message": err.Error()})
		return
	}

	type itemResult struct {
		Index         int            `json:"index"`
		ProfileID     string         `json:"profile_id,omitempty"`
		ProfileName   string         `json:"profile_name,omitempty"`
		Saved         bool           `json:"saved"`
		Enabled       bool           `json:"enabled"`
		Verified      bool           `json:"verified"`
		FailureReason string         `json:"failure_reason,omitempty"`
		HTTPSProbe    map[string]any `json:"https_probe,omitempty"`
	}
	results := make([]itemResult, 0, len(generation.Configs))
	var eligible []string
	modeLabel := map[string]string{"awg2": "AWG 2.0", "awg3": "AWG 3.0", "awg31": "AWG 3.1"}[mode]
	for i, generated := range generation.Configs {
		item := itemResult{Index: i + 1}
		_, normalized, decodeErr := decodeGeneratedConfig(generated.Content)
		if decodeErr != nil {
			item.FailureReason = decodeErr.Error()
			results = append(results, item)
			continue
		}
		id, path, storeErr := storeImportedProfile(s.dataDir, normalized)
		if storeErr != nil {
			item.FailureReason = "profile storage unavailable"
			results = append(results, item)
			continue
		}
		name := fmt.Sprintf("WARP %s %d", modeLabel, i+1)
		profile, addErr := s.controller.addDisabledRuntimeProfile(id, name, normalized, path)
		if addErr != nil {
			_ = os.Remove(path)
			item.FailureReason = "profile could not be added: " + addErr.Error()
			results = append(results, item)
			continue
		}
		item.ProfileID, item.ProfileName, item.Saved = id, name, true
		probeTimeout := s.controller.settings.Failover.ManualCheckTimeout
		if probeTimeout <= 0 {
			probeTimeout = 30 * time.Second
		}
		probeCtx, probeCancel := context.WithTimeout(workflowCtx, probeTimeout)
		probe, reason := s.controller.testGeneratedProfile(probeCtx, profile)
		probeCancel()
		item.HTTPSProbe = probe
		item.Verified = reason == ""
		if item.Verified {
			eligible = append(eligible, id)
		} else {
			item.FailureReason = reason
			profile.mu.Lock()
			profile.LastError = "Generated WARP profile failed HTTPS verification: " + reason
			profile.mu.Unlock()
		}
		results = append(results, item)
	}
	if err := s.persistState(); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "Generated configs were stored, but profile state could not be persisted."})
		return
	}
	response := map[string]any{
		"success": true, "mode": mode, "requested": req.Count, "generated": len(generation.Configs),
		"endpoint_mode": "hostname", "allowed_ips": "0.0.0.0/0", "experimental_cps": false,
		"profiles": results, "eligible_profile_ids": eligible,
		"message": "New profiles remain disabled. Enable only HTTPS-verified profiles if you want them considered by automatic failover.",
	}
	if warning, ok := generation.Warning.(string); ok && len(warning) <= 512 {
		response["generator_warning"] = warning
	}
	writeJSON(w, response)
}

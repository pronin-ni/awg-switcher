package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"
)

const maxWebsiteCount = 20
const maxWebsiteHistory = 20000
const maxWebsiteConfigBytes = 512 << 10

type Website struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Enabled  bool   `json:"enabled"`
	Required bool   `json:"required"`
	Statuses []int  `json:"expected_statuses"`
	Template bool   `json:"template,omitempty"`
}

type WebsiteSchedule struct {
	Mode     string `json:"mode"` // every, daily, cron
	Minutes  int    `json:"minutes,omitempty"`
	Hour     int    `json:"hour,omitempty"`
	Minute   int    `json:"minute,omitempty"`
	Cron     string `json:"cron,omitempty"`
	Timezone string `json:"timezone"`
	Paused   bool   `json:"paused"`
}

type WebsiteMonitorConfig struct {
	Enabled           bool            `json:"enabled"`
	Websites          []Website       `json:"websites"`
	TimeoutSeconds    int             `json:"timeout_seconds"`
	FailureThreshold  int             `json:"failure_threshold"`
	RecoveryThreshold int             `json:"recovery_threshold"`
	Policy            string          `json:"policy"` // all_required or minimum_passes
	MinimumPasses     int             `json:"minimum_passes,omitempty"`
	Schedule          WebsiteSchedule `json:"schedule"`
}

type WebsiteCheckResult struct {
	At          time.Time `json:"at"`
	ProfileID   string    `json:"profile_id"`
	ProfileName string    `json:"profile_name"`
	WebsiteID   string    `json:"website_id"`
	WebsiteName string    `json:"website_name"`
	URL         string    `json:"url"`
	Status      int       `json:"http_status,omitempty"`
	LatencyMS   int64     `json:"latency_ms"`
	TLS         string    `json:"tls"`
	Outcome     string    `json:"outcome"`
	Error       string    `json:"error,omitempty"`
	Failures    int       `json:"consecutive_failures"`
	Successes   int       `json:"consecutive_successes"`
}

type WebsiteProfileStatus struct {
	ProfileID        string               `json:"profile_id"`
	Connectivity     string               `json:"connectivity"`
	WebsiteHealth    string               `json:"website_health"`
	Routing          string               `json:"routing_eligibility"`
	Unavailable      []string             `json:"unavailable_sites"`
	LastCheck        time.Time            `json:"last_check,omitempty"`
	NextCheck        time.Time            `json:"next_check,omitempty"`
	Reason           string               `json:"reason,omitempty"`
	LastStatusChange time.Time            `json:"last_status_change,omitempty"`
	Results          []WebsiteCheckResult `json:"results"`
	SuccessCount     int                  `json:"success_count"`
	ErrorCount       int                  `json:"error_count"`
	AverageLatency   float64              `json:"average_latency_ms"`
}

var websiteTemplates = []Website{
	{ID: "template-rutracker", Name: "Rutracker", URL: "https://rutracker.org/", Statuses: statusRange(200, 399), Template: true},
	{ID: "template-facebook", Name: "Facebook", URL: "https://www.facebook.com/", Statuses: statusRange(200, 399), Template: true},
	{ID: "template-radarr", Name: "Radarr API", URL: "https://api.radarr.video/v1/search?q=xt", Statuses: statusRange(200, 399), Template: true},
	{ID: "template-github", Name: "GitHub API", URL: "https://api.github.com/", Statuses: statusRange(200, 399), Template: true},
}

func statusRange(from, to int) []int {
	out := make([]int, 0, to-from+1)
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func defaultWebsiteMonitorConfig() WebsiteMonitorConfig {
	return WebsiteMonitorConfig{Websites: []Website{}, TimeoutSeconds: 15, FailureThreshold: 2, RecoveryThreshold: 2, Policy: "all_required", Schedule: WebsiteSchedule{Mode: "every", Minutes: 30, Timezone: "UTC"}}
}

func validateWebsiteConfig(c WebsiteMonitorConfig) error {
	if len(c.Websites) > maxWebsiteCount {
		return fmt.Errorf("maximum %d website checks", maxWebsiteCount)
	}
	if c.TimeoutSeconds < 2 || c.TimeoutSeconds > 60 {
		return errors.New("timeout_seconds must be between 2 and 60")
	}
	if c.FailureThreshold < 1 || c.FailureThreshold > 20 || c.RecoveryThreshold < 1 || c.RecoveryThreshold > 20 {
		return errors.New("failure and recovery thresholds must be between 1 and 20")
	}
	if c.Policy != "all_required" && c.Policy != "minimum_passes" {
		return errors.New("policy must be all_required or minimum_passes")
	}
	if c.Policy == "minimum_passes" && (c.MinimumPasses < 1 || c.MinimumPasses > maxWebsiteCount) {
		return errors.New("minimum_passes must be between 1 and 20")
	}
	if c.Enabled && c.Policy == "minimum_passes" && c.MinimumPasses > enabledWebsites(c) {
		return errors.New("minimum_passes cannot exceed the number of enabled websites")
	}
	ids := map[string]bool{}
	for i := range c.Websites {
		w := &c.Websites[i]
		w.ID = strings.TrimSpace(w.ID)
		w.Name = strings.TrimSpace(w.Name)
		if w.ID == "" || len(w.ID) > 80 || ids[w.ID] {
			return errors.New("website IDs must be unique and non-empty")
		}
		ids[w.ID] = true
		if w.Name == "" || len(w.Name) > 100 {
			return errors.New("website name is required and must be at most 100 characters")
		}
		if len(w.URL) > 2048 {
			return fmt.Errorf("%s: URL is too long", w.Name)
		}
		u, err := url.Parse(w.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Port() != "" && u.Port() != "443" {
			return fmt.Errorf("%s: URL must be a public HTTPS URL without credentials or a non-standard port", w.Name)
		}
		if _, err := strconv.Atoi(u.Port()); u.Port() != "" && err != nil {
			return fmt.Errorf("%s: invalid port", w.Name)
		}
		if len(w.Statuses) == 0 || len(w.Statuses) > 500 {
			return fmt.Errorf("%s: choose 1 to 500 accepted HTTP statuses", w.Name)
		}
		seen := map[int]bool{}
		for _, status := range w.Statuses {
			if status < 100 || status > 599 || seen[status] {
				return fmt.Errorf("%s: invalid or duplicate HTTP status", w.Name)
			}
			seen[status] = true
		}
	}
	if c.Schedule.Timezone == "" {
		return errors.New("timezone is required")
	}
	if _, err := time.LoadLocation(c.Schedule.Timezone); err != nil {
		return errors.New("unknown timezone")
	}
	switch c.Schedule.Mode {
	case "every":
		if c.Schedule.Minutes < 1 || c.Schedule.Minutes > 1440 {
			return errors.New("schedule minutes must be between 1 and 1440")
		}
	case "daily":
		if c.Schedule.Hour < 0 || c.Schedule.Hour > 23 || c.Schedule.Minute < 0 || c.Schedule.Minute > 59 {
			return errors.New("daily schedule hour/minute is invalid")
		}
	case "cron":
		if _, err := nextCronTime(time.Now(), c.Schedule.Cron, c.Schedule.Timezone); err != nil {
			return err
		}
	default:
		return errors.New("schedule mode must be every, daily or cron")
	}
	return nil
}

func (c *Controller) loadWebsiteMonitor(dataDir string) error {
	c.websiteDataDir = dataDir
	cfg := defaultWebsiteMonitorConfig()
	path := filepath.Join(dataDir, "website-monitor.json")
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxWebsiteConfigBytes {
			return errors.New("website monitor settings permissions are unsafe")
		}
		if err = json.Unmarshal(b, &cfg); err != nil {
			return errors.New("website monitor settings are invalid")
		}
		if err = validateWebsiteConfig(cfg); err != nil {
			return fmt.Errorf("website monitor settings: %w", err)
		}
	}
	c.websiteMu.Lock()
	c.websiteConfig = cfg
	c.websiteStatuses = make(map[string]WebsiteProfileStatus)
	c.websiteMu.Unlock()
	return nil
}

func (c *Controller) saveWebsiteMonitor(cfg WebsiteMonitorConfig) error {
	if err := validateWebsiteConfig(cfg); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > maxWebsiteConfigBytes {
		return errors.New("website monitor settings exceed size limit")
	}
	if err = os.MkdirAll(c.websiteDataDir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(c.websiteDataDir, ".website-monitor-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(c.websiteDataDir, "website-monitor.json"))
}

func (c *Controller) websiteConfigSnapshot() WebsiteMonitorConfig {
	c.websiteMu.RLock()
	defer c.websiteMu.RUnlock()
	return cloneWebsiteConfig(c.websiteConfig)
}
func cloneWebsiteConfig(c WebsiteMonitorConfig) WebsiteMonitorConfig {
	c.Websites = append([]Website{}, c.Websites...)
	for i := range c.Websites {
		c.Websites[i].Statuses = append([]int(nil), c.Websites[i].Statuses...)
	}
	return c
}

func (c *Controller) startWebsiteMonitor(ctx context.Context) {
	c.websiteMu.Lock()
	if c.websiteRunning {
		c.websiteMu.Unlock()
		return
	}
	c.websiteRunning = true
	if c.websiteWake == nil {
		c.websiteWake = make(chan struct{}, 1)
	}
	c.websiteMu.Unlock()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		// Never trust persisted PASS as an indefinite permission after restart.
		if cfg := c.websiteConfigSnapshot(); cfg.Enabled && enabledWebsites(cfg) > 0 {
			deadline := time.NewTimer(60 * time.Second)
		waitEngines:
			for {
				allStarted := true
				for _, p := range c.profilesSnapshot() {
					p.mu.Lock()
					on, session := p.enabled, p.session
					p.mu.Unlock()
					if on && session == nil {
						allStarted = false
						break
					}
				}
				if allStarted {
					break
				}
				select {
				case <-ctx.Done():
					deadline.Stop()
					return
				case <-deadline.C:
					break waitEngines
				case <-time.After(250 * time.Millisecond):
				}
			}
			deadline.Stop()
			_ = c.runWebsiteChecks(ctx)
		}
		for {
			cfg := c.websiteConfigSnapshot()
			next := time.Time{}
			c.websiteMu.Lock()
			paused := c.websitePaused || cfg.Schedule.Paused
			if !paused && cfg.Enabled && enabledWebsites(cfg) > 0 {
				next = nextWebsiteTime(time.Now(), cfg.Schedule)
			}
			c.websiteNextCheck = next
			c.websiteMu.Unlock()
			if paused || next.IsZero() {
				select {
				case <-ctx.Done():
					return
				case <-c.websiteWake:
					continue
				case <-time.After(time.Minute):
					continue
				}
			}
			d := time.Until(next)
			if d < 0 {
				d = 0
			}
			select {
			case <-ctx.Done():
				return
			case <-c.websiteWake:
				continue
			case <-time.After(d):
				_ = c.runWebsiteChecks(ctx)
			}
		}
	}()
}

func enabledWebsites(c WebsiteMonitorConfig) int {
	n := 0
	for _, w := range c.Websites {
		if w.Enabled {
			n++
		}
	}
	return n
}

func websitePolicyApplies(cfg WebsiteMonitorConfig) bool {
	if !cfg.Enabled {
		return false
	}
	if cfg.Policy == "minimum_passes" {
		return cfg.MinimumPasses > 0 && enabledWebsites(cfg) > 0
	}
	for _, w := range cfg.Websites {
		if w.Enabled && w.Required {
			return true
		}
	}
	return false
}

func nextWebsiteTime(now time.Time, s WebsiteSchedule) time.Time {
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		loc = time.UTC
	}
	local := now.In(loc)
	switch s.Mode {
	case "every":
		return now.Add(time.Duration(s.Minutes) * time.Minute)
	case "daily":
		candidate := time.Date(local.Year(), local.Month(), local.Day(), s.Hour, s.Minute, 0, 0, loc)
		if !candidate.After(local) {
			candidate = candidate.AddDate(0, 0, 1)
		}
		return candidate
	case "cron":
		t, err := nextCronTime(now, s.Cron, s.Timezone)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

func cronFieldMatches(field string, value, min, max int) bool {
	for _, part := range strings.Split(field, ",") {
		step := 1
		base := part
		if strings.Contains(part, "/") {
			pieces := strings.SplitN(part, "/", 2)
			base = pieces[0]
			v, e := strconv.Atoi(pieces[1])
			if e != nil || v < 1 {
				return false
			}
			step = v
		}
		lo, hi := min, max
		if base != "*" {
			if strings.Contains(base, "-") {
				p := strings.SplitN(base, "-", 2)
				a, e1 := strconv.Atoi(p[0])
				b, e2 := strconv.Atoi(p[1])
				if e1 != nil || e2 != nil {
					return false
				}
				lo, hi = a, b
			} else {
				v, e := strconv.Atoi(base)
				if e != nil {
					return false
				}
				lo, hi = v, v
				if strings.Contains(part, "/") {
					hi = max
				}
			}
		}
		if lo < min || hi > max || lo > hi {
			return false
		}
		if value >= lo && value <= hi && (value-lo)%step == 0 {
			return true
		}
	}
	return false
}

func validCronField(field string, min, max int) bool {
	if field == "" {
		return false
	}
	for _, part := range strings.Split(field, ",") {
		if part == "" {
			return false
		}
		step := 1
		base := part
		if strings.Contains(part, "/") {
			x := strings.Split(part, "/")
			if len(x) != 2 {
				return false
			}
			base = x[0]
			n, e := strconv.Atoi(x[1])
			if e != nil || n < 1 || n > 10000 {
				return false
			}
			step = n
		}
		if base == "*" {
			continue
		}
		lo, hi := 0, 0
		if strings.Contains(base, "-") {
			x := strings.Split(base, "-")
			if len(x) != 2 {
				return false
			}
			var e error
			lo, e = strconv.Atoi(x[0])
			if e != nil {
				return false
			}
			hi, e = strconv.Atoi(x[1])
			if e != nil {
				return false
			}
		} else {
			n, e := strconv.Atoi(base)
			if e != nil {
				return false
			}
			lo, hi = n, n
		}
		if lo < min || hi > max || lo > hi {
			return false
		}
		_ = step
	}
	return true
}

func nextCronTime(now time.Time, expr, zone string) (time.Time, error) {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return time.Time{}, errors.New("cron must contain five fields: minute hour day month weekday")
	}
	limits := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 6}}
	for i, field := range f {
		if !validCronField(field, limits[i][0], limits[i][1]) {
			return time.Time{}, errors.New("invalid cron expression")
		}
	}
	loc, e := time.LoadLocation(zone)
	if e != nil {
		return time.Time{}, errors.New("unknown cron timezone")
	}
	t := now.In(loc).Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < 366*24*60; i++ {
		if cronFieldMatches(f[0], t.Minute(), 0, 59) && cronFieldMatches(f[1], t.Hour(), 0, 23) && cronFieldMatches(f[2], t.Day(), 1, 31) && cronFieldMatches(f[3], int(t.Month()), 1, 12) && cronFieldMatches(f[4], int(t.Weekday()), 0, 6) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, errors.New("cron expression has no run time in the next year")
}

func isPublicIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	blocked := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32", "2001::/23", "2002::/16", "64:ff9b::/96"}
	for _, raw := range blocked {
		_, n, _ := net.ParseCIDR(raw)
		if n != nil && n.Contains(ip) {
			return false
		}
	}
	return true
}

func (c *Controller) resolveWebsiteHost(ctx context.Context, p *Profile, host string) ([]net.IP, error) {
	var addresses []net.IP
	var err error
	if c.websiteResolver != nil {
		addresses, err = c.websiteResolver(ctx, host)
	} else {
		addresses, err = c.resolveWebsiteHostThroughProfile(ctx, p, host)
	}
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("DNS returned no addresses")
	}
	for _, ip := range addresses {
		if !isPublicIP(ip) {
			return nil, errors.New("hostname resolves to a non-public address")
		}
	}
	return addresses, nil
}

// resolveWebsiteHostThroughProfile keeps destination DNS queries inside the
// selected VPN route. The system resolver is intentionally not used for the
// website being measured; only the DoH endpoint hostname is resolved by the
// remote SOCKS engine.
func (c *Controller) resolveWebsiteHostThroughProfile(ctx context.Context, p *Profile, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return nil, errors.New("destination is not a public address")
		}
		return []net.IP{ip}, nil
	}
	p.mu.Lock()
	session := p.session
	p.mu.Unlock()
	if session == nil {
		return nil, errors.New("VPN engine is not running")
	}
	endpoint := c.websiteDNSURL
	if endpoint == "" {
		endpoint = "https://cloudflare-dns.com/dns-query"
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.websiteTLSConfig != nil {
		tlsConfig = c.websiteTLSConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, DialContext: func(dctx context.Context, network, address string) (net.Conn, error) {
		return c.socksDialAt(dctx, session.SOCKSAddr(), address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var out []net.IP
	for _, qtype := range []string{"A", "AAAA"} {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, errors.New("DNS-over-HTTPS endpoint is invalid")
		}
		q := u.Query()
		q.Set("name", host)
		q.Set("type", qtype)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, errors.New("DNS-over-HTTPS request failed")
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("DNS-over-HTTPS failed through VPN: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DNS-over-HTTPS returned HTTP %d", resp.StatusCode)
		}
		var answer struct {
			Status  int `json:"Status"`
			Answers []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if json.Unmarshal(body, &answer) != nil || answer.Status != 0 {
			return nil, errors.New("DNS-over-HTTPS returned an invalid DNS response")
		}
		for _, record := range answer.Answers {
			if record.Type != 1 && record.Type != 28 {
				continue
			}
			ip := net.ParseIP(record.Data)
			if ip == nil {
				return nil, errors.New("DNS-over-HTTPS returned an invalid address")
			}
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("DNS-over-HTTPS returned no addresses")
	}
	return out, nil
}

func sanitizedWebsiteURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

type websiteProbe struct {
	result WebsiteCheckResult
	ok     bool
}

func (c *Controller) probeWebsite(ctx context.Context, p *Profile, w Website, timeout time.Duration) websiteProbe {
	started := time.Now()
	out := WebsiteCheckResult{At: started.UTC(), ProfileID: p.ID, ProfileName: p.Name, WebsiteID: w.ID, WebsiteName: w.Name, URL: sanitizedWebsiteURL(w.URL), TLS: "not_checked"}
	current, err := url.Parse(w.URL)
	if err != nil {
		out.Error = "invalid URL"
		return websiteProbe{out, false}
	}
	for redirects := 0; redirects <= 5; redirects++ {
		if current.Scheme != "https" || current.User != nil || current.Hostname() == "" {
			out.Error = "redirect must target public HTTPS without credentials"
			break
		}
		ips, resolveErr := c.resolveWebsiteHost(ctx, p, current.Hostname())
		if resolveErr != nil {
			out.Error = resolveErr.Error()
			if strings.Contains(out.Error, "DNS") {
				out.TLS = "not_reached"
			}
			break
		}
		port := current.Port()
		if port == "" {
			port = "443"
		}
		if port != "443" {
			out.Error = "HTTPS destination must use port 443"
			break
		}
		target := net.JoinHostPort(ips[0].String(), port)
		p.mu.Lock()
		session := p.session
		p.mu.Unlock()
		if session == nil {
			out.Error = "VPN engine is not running"
			break
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if c.websiteTLSConfig != nil {
			tlsConfig = c.websiteTLSConfig.Clone()
			if tlsConfig.MinVersion == 0 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableKeepAlives: true, DialContext: func(dctx context.Context, network, address string) (net.Conn, error) {
			return c.socksDialAt(dctx, session.SOCKSAddr(), target)
		}}
		client := http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if e != nil {
			transport.CloseIdleConnections()
			out.Error = "request creation failed"
			break
		}
		req.Header.Set("User-Agent", "AWG-Switcher-Website-Monitor/1.0")
		req.Header.Set("Accept", "*/*")
		resp, e := client.Do(req)
		transport.CloseIdleConnections()
		if e != nil {
			out.Error = classifyHealthError(e)
			if errors.Is(e, context.DeadlineExceeded) || strings.Contains(strings.ToLower(e.Error()), "timeout") {
				out.Error = "timeout"
			}
			if strings.Contains(strings.ToLower(e.Error()), "tls") || strings.Contains(strings.ToLower(e.Error()), "certificate") {
				out.TLS = "failed"
			} else {
				out.TLS = "not_completed"
			}
			break
		}
		out.TLS = "verified"
		out.Status = resp.StatusCode
		out.LatencyMS = time.Since(started).Milliseconds()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		for _, status := range w.Statuses {
			if status == resp.StatusCode {
				out.Outcome = "PASS"
				return websiteProbe{out, true}
			}
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location, e := resp.Location()
			if e != nil {
				out.Error = "invalid redirect"
				break
			}
			if redirects == 5 {
				out.Error = "too many redirects"
				break
			}
			current = current.ResolveReference(location)
			continue
		}
		out.Error = fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
		break
	}
	out.LatencyMS = time.Since(started).Milliseconds()
	out.Outcome = "FAIL"
	return websiteProbe{out, false}
}

func websiteProfileEligible(cfg WebsiteMonitorConfig, results []WebsiteCheckResult, websites []Website) (bool, string, string, []string) {
	required := 0
	passed := 0
	var unavailable []string
	firstReason := ""
	byID := map[string]WebsiteCheckResult{}
	for _, r := range results {
		byID[r.WebsiteID] = r
	}
	for _, w := range websites {
		if !w.Enabled {
			continue
		}
		r, ok := byID[w.ID]
		if !ok {
			continue
		}
		if w.Required {
			required++
		}
		if r.Outcome == "PASS" {
			passed++
		} else {
			unavailable = append(unavailable, w.Name)
			if firstReason == "" {
				firstReason = w.Name + ": " + r.Error
			}
		}
	}
	if cfg.Policy == "all_required" {
		if required == 0 {
			return true, "PASSED", "", unavailable
		}
		for _, w := range websites {
			if w.Enabled && w.Required {
				r, ok := byID[w.ID]
				if !ok || r.Outcome != "PASS" {
					if firstReason == "" {
						firstReason = w.Name + ": pending"
					}
					return false, "FAILED", firstReason, unavailable
				}
			}
		}
		return true, "PASSED", "", unavailable
	}
	if passed >= cfg.MinimumPasses {
		return true, "PASSED", "", unavailable
	}
	return false, "FAILED", firstReason, unavailable
}

func (c *Controller) runWebsiteChecks(ctx context.Context) error {
	c.websiteRunMu.Lock()
	defer c.websiteRunMu.Unlock()
	return c.runWebsiteChecksLocked(ctx, nil)
}

// runWebsiteChecksFor is used only to qualify a newly added profile without
// probing or changing the health state of existing profiles outside schedule.
func (c *Controller) runWebsiteChecksFor(ctx context.Context, onlyIDs []string) error {
	c.websiteRunMu.Lock()
	defer c.websiteRunMu.Unlock()
	return c.runWebsiteChecksLocked(ctx, onlyIDs)
}

func (c *Controller) runWebsiteChecksLocked(ctx context.Context, onlyIDs []string) error {
	cfg := c.websiteConfigSnapshot()
	if !cfg.Enabled {
		return errors.New("website monitor is disabled")
	}
	websites := make([]Website, 0)
	for _, w := range cfg.Websites {
		if w.Enabled {
			websites = append(websites, w)
		}
	}
	if len(websites) == 0 {
		return errors.New("no enabled websites")
	}
	started := time.Now().UTC()
	c.websiteMu.Lock()
	c.websiteLastCheck = started
	c.websiteLastError = ""
	c.websiteMu.Unlock()
	profiles := c.profilesSnapshot()
	if onlyIDs != nil {
		wanted := map[string]bool{}
		for _, id := range onlyIDs {
			wanted[id] = true
		}
		filtered := profiles[:0]
		for _, p := range profiles {
			if wanted[p.ID] {
				filtered = append(filtered, p)
			}
		}
		profiles = filtered
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var resultsMu sync.Mutex
	byProfile := map[string][]WebsiteCheckResult{}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	for _, p := range profiles {
		p.mu.Lock()
		enabled := p.enabled
		p.mu.Unlock()
		if !enabled {
			continue
		}
		for _, w := range websites {
			wg.Add(1)
			go func(p *Profile, w Website) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				pc, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				probe := c.probeWebsite(pc, p, w, timeout)
				resultsMu.Lock()
				byProfile[p.ID] = append(byProfile[p.ID], probe.result)
				resultsMu.Unlock()
			}(p, w)
		}
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	nextCheck := nextWebsiteTime(now, cfg.Schedule)
	if onlyIDs != nil {
		c.websiteMu.RLock()
		nextCheck = c.websiteNextCheck
		c.websiteMu.RUnlock()
	}
	for _, p := range profiles {
		p.mu.Lock()
		enabled := p.enabled
		connOK := p.Healthy
		p.mu.Unlock()
		if !enabled {
			continue
		}
		rows := byProfile[p.ID]
		currentOK, _, reason, unavailable := websiteProfileEligible(cfg, rows, websites)
		c.websiteMu.RLock()
		previousChange := c.websiteStatuses[p.ID].LastStatusChange
		c.websiteMu.RUnlock()
		p.mu.Lock()
		if p.websiteFailures == nil {
			p.websiteFailures = map[string]int{}
		}
		if p.websiteSuccesses == nil {
			p.websiteSuccesses = map[string]int{}
		}
		for i := range rows {
			r := &rows[i]
			if r.Outcome == "PASS" {
				p.websiteSuccesses[r.WebsiteID]++
				p.websiteFailures[r.WebsiteID] = 0
			} else {
				p.websiteFailures[r.WebsiteID]++
				p.websiteSuccesses[r.WebsiteID] = 0
			}
			r.Failures = p.websiteFailures[r.WebsiteID]
			r.Successes = p.websiteSuccesses[r.WebsiteID]
		}
		oldState := p.WebsiteState
		wasEligible := p.RoutingEligible
		if currentOK {
			p.websiteSuccessCycles++
			p.websiteFailureCycles = 0
		} else {
			p.websiteFailureCycles++
			p.websiteSuccessCycles = 0
		}
		state := "PENDING"
		routing := false
		if currentOK {
			if p.websiteRecoveryPending && p.websiteSuccessCycles < cfg.RecoveryThreshold {
				state = "PENDING"
			} else {
				state = "PASSED"
				if len(unavailable) > 0 {
					state = "DEGRADED"
				}
				routing = true
				p.websiteRecoveryPending = false
			}
		} else if p.websiteFailureCycles >= cfg.FailureThreshold {
			state = "FAILED"
			p.websiteRecoveryPending = true
		} else {
			state = "DEGRADED"
			routing = wasEligible
		}
		p.WebsiteState = state
		p.WebsiteReason = reason
		p.WebsiteLastCheck = now
		p.RoutingEligible = connOK && routing
		status := WebsiteProfileStatus{ProfileID: p.ID, Connectivity: map[bool]string{true: "HEALTHY", false: "UNHEALTHY"}[connOK], WebsiteHealth: state, Routing: map[bool]string{true: "ELIGIBLE", false: "BLOCKED"}[p.RoutingEligible], Unavailable: unavailable, LastCheck: now, NextCheck: nextCheck, Reason: reason, Results: rows}
		if oldState != state {
			status.LastStatusChange = now
		} else {
			status.LastStatusChange = previousChange
		}
		var latency int64
		for _, r := range rows {
			if r.Outcome == "PASS" {
				status.SuccessCount++
			} else {
				status.ErrorCount++
			}
			latency += r.LatencyMS
		}
		if len(rows) > 0 {
			status.AverageLatency = float64(latency) / float64(len(rows))
		}
		p.mu.Unlock()
		c.websiteMu.Lock()
		if c.websiteStatuses == nil {
			c.websiteStatuses = make(map[string]WebsiteProfileStatus)
		}
		c.websiteStatuses[p.ID] = status
		c.websiteHistory = append(c.websiteHistory, rows...)
		c.websiteMu.Unlock()
		if state == "FAILED" && oldState != "FAILED" {
			c.appendEvent(ControllerEvent{At: now, Kind: "website_blocked", Profile: p.ID, Message: "Website policy blocked routing: " + reason})
		}
		if state == "PASSED" && oldState == "FAILED" {
			c.appendEvent(ControllerEvent{At: now, Kind: "website_recovered", Profile: p.ID, Message: "Website policy recovered: required sites passed"})
		}
	}
	c.websiteMu.Lock()
	if len(c.websiteHistory) > maxWebsiteHistory {
		c.websiteHistory = append([]WebsiteCheckResult(nil), c.websiteHistory[len(c.websiteHistory)-maxWebsiteHistory:]...)
	}
	c.websiteLastCheck = now
	if onlyIDs == nil {
		c.websiteNextCheck = nextWebsiteTime(now, cfg.Schedule)
	}
	c.websiteMu.Unlock()
	// Re-evaluate immediately. A confirmed website policy failure is an emergency route exclusion.
	c.selectProfile()
	if c.onEvent != nil {
		go c.onEvent()
	}
	if c.onWebsiteState != nil {
		c.onWebsiteState()
	}
	return nil
}

func (c *Controller) websiteStatusesSnapshot() []WebsiteProfileStatus {
	c.websiteMu.RLock()
	defer c.websiteMu.RUnlock()
	out := make([]WebsiteProfileStatus, 0, len(c.websiteStatuses))
	for _, s := range c.websiteStatuses {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out
}

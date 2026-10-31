package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type Settings struct {
	Proxy struct {
		HTTPPort int `yaml:"http_port"`
	} `yaml:"proxy"`
	Profiles struct {
		Directory string   `yaml:"directory"`
		Primary   string   `yaml:"primary"`
		Priority  []string `yaml:"priority"`
	} `yaml:"profiles"`
	Failover struct {
		Enabled           bool          `yaml:"enabled"`
		CheckInterval     time.Duration `yaml:"check_interval"`
		CheckTimeout      time.Duration `yaml:"check_timeout"`
		FailureThreshold  int           `yaml:"failure_threshold"`
		RecoveryThreshold int           `yaml:"recovery_threshold"`
		RecoveryInterval  time.Duration `yaml:"recovery_interval"`
		SwitchCooldown    time.Duration `yaml:"switch_cooldown"`
	} `yaml:"failover"`
	Health struct {
		URLs              []string `yaml:"urls"`
		RequiredSuccesses int      `yaml:"required_successes"`
	} `yaml:"health"`
}

type Profile struct {
	Name            string    `json:"name"`
	ID              string    `json:"id"`
	Priority        int       `json:"priority"`
	State           string    `json:"state"`
	Healthy         bool      `json:"healthy"`
	LastError       string    `json:"last_error,omitempty"`
	LastCheck       time.Time `json:"last_check,omitempty"`
	LastSuccess     time.Time `json:"last_success,omitempty"`
	HealthLatencyMS int64     `json:"health_latency_ms,omitempty"`
	Failures        int       `json:"failures"`
	Successes       int       `json:"successes"`
	Restarts        int       `json:"restarts"`
	path            string
	config          []byte
	socks           string
	session         EngineSession
	restartReq      chan struct{}
	restartTimes    []time.Time
	transport       *http.Transport
	mu              sync.Mutex
}
type Snapshot struct {
	Active   string     `json:"active,omitempty"`
	Profiles []*Profile `json:"profiles"`
	Since    time.Time  `json:"since"`
	Switches uint64     `json:"switches"`
}
type Controller struct {
	profiles   []*Profile
	active     atomic.Pointer[Profile]
	settings   Settings
	started    time.Time
	switches   atomic.Uint64
	mu         sync.Mutex
	lastSwitch time.Time
	engine     Engine
	runtimeDir string
	maxEngines int
	requests   chan struct{}
	wg         sync.WaitGroup
}

func defaults(s *Settings) {
	if s.Proxy.HTTPPort == 0 {
		s.Proxy.HTTPPort = 20171
	}
	if s.Profiles.Directory == "" {
		s.Profiles.Directory = "/app/configs"
	}
	if s.Failover.CheckInterval == 0 {
		s.Failover.CheckInterval = 15 * time.Second
	}
	if s.Failover.CheckTimeout == 0 {
		s.Failover.CheckTimeout = 8 * time.Second
	}
	if s.Failover.FailureThreshold == 0 {
		s.Failover.FailureThreshold = 2
	}
	if s.Failover.RecoveryThreshold == 0 {
		s.Failover.RecoveryThreshold = 3
	}
	if s.Failover.RecoveryInterval == 0 {
		s.Failover.RecoveryInterval = 60 * time.Second
	}
	if s.Failover.SwitchCooldown == 0 {
		s.Failover.SwitchCooldown = 30 * time.Second
	}
	if len(s.Health.URLs) == 0 {
		s.Health.URLs = []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://api.ipify.org"}
	}
	if s.Health.RequiredSuccesses == 0 {
		s.Health.RequiredSuccesses = 1
	}
}
func loadSettings() (Settings, error) {
	s := Settings{}
	b, e := os.ReadFile("/app/settings.yaml")
	if e == nil {
		if e = yaml.Unmarshal(b, &s); e != nil {
			return s, e
		}
		var presence map[string]map[string]any
		if e = yaml.Unmarshal(b, &presence); e != nil {
			return s, e
		}
		if failover, ok := presence["failover"]; !ok || failover["enabled"] == nil {
			s.Failover.Enabled = true
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return s, e
	} else {
		s.Failover.Enabled = true
	}
	defaults(&s)
	if s.Proxy.HTTPPort < 1 || s.Proxy.HTTPPort > 65535 || s.Failover.CheckTimeout <= 0 || s.Failover.CheckInterval <= 0 || s.Failover.FailureThreshold < 1 || s.Failover.RecoveryThreshold < 1 || s.Failover.RecoveryInterval <= 0 || s.Failover.SwitchCooldown < 0 || s.Health.RequiredSuccesses < 1 {
		return s, errors.New("invalid settings value")
	}
	for _, raw := range s.Health.URLs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return s, errors.New("health URLs must be HTTPS URLs without credentials")
		}
	}
	return s, nil
}

// normalizeWG validates known WireGuard/AWG keys and converts bare addresses to host prefixes.
func normalizeWG(data []byte) ([]byte, error) {
	known := map[string]bool{"address": true, "privatekey": true, "listenport": true, "dns": true, "mtu": true, "publickey": true, "presharedkey": true, "endpoint": true, "allowedips": true, "persistentkeepalive": true, "jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true, "s3": true, "s4": true, "h1": true, "h2": true, "h3": true, "h4": true, "i1": true, "i2": true, "i3": true, "i4": true, "i5": true, "headerprotectionkey": true, "contentpaddingaddition": true, "rekeyaftertime": true, "rekeytimeout": true, "rejectaftertime": true, "keepalivetimeout": true, "maxhandshakeattempts": true, "randomtrailers": true, "disablecookies": true}
	var out []string
	section := ""
	hasKey, hasPeer := false, false
	for n, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			out = append(out, line)
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			section = strings.ToLower(trim[1 : len(trim)-1])
			if section != "interface" && section != "peer" {
				return nil, fmt.Errorf("line %d: unsupported section", n+1)
			}
			if section == "peer" {
				hasPeer = true
			}
			out = append(out, line)
			continue
		}
		k, v, ok := strings.Cut(trim, "=")
		if !ok || section == "" {
			return nil, fmt.Errorf("line %d: malformed setting", n+1)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if !known[key] {
			return nil, fmt.Errorf("line %d: unsupported setting %q", n+1, strings.TrimSpace(k))
		}
		if section == "interface" {
			hasKey = hasKey || key == "privatekey"
			if key == "address" {
				var addrs []string
				for _, a := range strings.Split(strings.TrimSpace(v), ",") {
					a = strings.TrimSpace(a)
					if !strings.Contains(a, "/") {
						ip := net.ParseIP(a)
						if ip == nil {
							return nil, fmt.Errorf("line %d: invalid Address", n+1)
						}
						bits := 128
						if ip.To4() != nil {
							bits = 32
						}
						a = fmt.Sprintf("%s/%d", a, bits)
					}
					if _, _, e := net.ParseCIDR(a); e != nil {
						return nil, fmt.Errorf("line %d: invalid Address", n+1)
					}
					addrs = append(addrs, a)
				}
				line = k + " = " + strings.Join(addrs, ", ")
			}
		}
		if section == "peer" && key == "endpoint" {
			ep := strings.TrimSpace(v)
			if _, _, e := net.SplitHostPort(ep); e != nil {
				return nil, fmt.Errorf("line %d: invalid Endpoint", n+1)
			}
		}
		out = append(out, line)
	}
	if !hasKey || !hasPeer {
		return nil, errors.New("required [Interface] PrivateKey and [Peer] missing")
	}
	return []byte(strings.Join(out, "\n")), nil
}

func discover(s Settings) ([]*Profile, error) {
	dir, e := filepath.Abs(s.Profiles.Directory)
	if e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	ranks := map[string]int{}
	for i, n := range s.Profiles.Priority {
		ranks[n] = i
	}
	if s.Profiles.Primary != "" {
		ranks[s.Profiles.Primary] = -1
	}
	var ps []*Profile
	seen := map[string]bool{}
	for _, entry := range entries {
		n := entry.Name()
		if !strings.HasSuffix(strings.ToLower(n), ".conf") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			slog.Warn("profile ignored", "profile", n, "reason", "not a regular file")
			continue
		}
		p := filepath.Join(dir, n)
		real, e := filepath.EvalSymlinks(p)
		if e != nil || !strings.HasPrefix(real, dir+string(os.PathSeparator)) {
			continue
		}
		b, e := os.ReadFile(real)
		if e != nil {
			continue
		}
		norm, e := normalizeWG(b)
		if e != nil {
			slog.Error("profile invalid", "profile", n, "reason", e)
			continue
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		rank, ok := ranks[n]
		if !ok {
			rank = 1000
		}
		ps = append(ps, &Profile{Name: n, ID: n, Priority: rank, State: "STARTING", path: real, config: norm, restartReq: make(chan struct{}, 1)})
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Priority == ps[j].Priority {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].Priority < ps[j].Priority
	})
	if len(ps) == 0 {
		return nil, errors.New("no valid WireGuard profiles found")
	}
	return ps, nil
}

func (c *Controller) start(ctx context.Context) {
	if c.runtimeDir == "" {
		c.runtimeDir = "/run/awg-switcher"
	}
	if c.engine == nil {
		c.engine = ProcessEngine{Binary: "/usr/local/bin/wireproxy", RuntimeDir: c.runtimeDir}
	}
	if c.maxEngines <= 0 {
		c.maxEngines = len(c.profiles)
	}
	if c.requests == nil {
		c.requests = make(chan struct{}, 512)
	}
	if err := os.MkdirAll(c.runtimeDir, 0700); err != nil {
		slog.Error("runtime directory unavailable", "error", err)
	}
	for i, p := range c.profiles {
		if i >= c.maxEngines {
			p.State = "DISABLED"
			p.LastError = "concurrent engine limit reached"
			continue
		}
		p.socks = fmt.Sprintf("127.0.0.1:%d", 21000+i)
		p.transport = &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return c.socksDial(ctx, p, address)
			},
			TLSHandshakeTimeout:   c.settings.Failover.CheckTimeout,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          32,
			MaxIdleConnsPerHost:   4,
		}
		c.wg.Add(1)
		go c.supervise(ctx, p, i)
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.monitor(ctx)
	}()
}

func (c *Controller) socksDial(ctx context.Context, p *Profile, address string) (net.Conn, error) {
	p.mu.Lock()
	addr := p.socks
	p.mu.Unlock()
	return c.socksDialAt(ctx, addr, address)
}

func (c *Controller) socksDialAt(ctx context.Context, socksAddr, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: c.settings.Failover.CheckTimeout}
	conn, e := d.DialContext(ctx, "tcp", socksAddr)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (net.Conn, error) { conn.Close(); return nil, e }
	_ = conn.SetDeadline(time.Now().Add(c.settings.Failover.CheckTimeout))
	if _, e = conn.Write([]byte{5, 1, 0}); e != nil {
		return fail(e)
	}
	var ans [2]byte
	if _, e = ioReadFull(conn, ans[:]); e != nil || ans != [2]byte{5, 0} {
		return fail(errors.New("SOCKS negotiation failed"))
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return fail(e)
	}
	pn, e := strconv.Atoi(port)
	if e != nil || pn < 1 || pn > 65535 {
		return fail(errors.New("invalid destination port"))
	}
	ip := net.ParseIP(host)
	req := []byte{5, 1, 0}
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 1)
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append(req, 4)
		req = append(req, ip6...)
	} else {
		if len(host) > 255 {
			return fail(errors.New("hostname too long"))
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(pn>>8), byte(pn))
	if _, e = conn.Write(req); e != nil {
		return fail(e)
	}
	var head [4]byte
	if _, e = ioReadFull(conn, head[:]); e != nil || head[1] != 0 {
		return fail(errors.New("SOCKS connect failed"))
	}
	switch head[3] {
	case 1:
		_, e = ioReadFull(conn, make([]byte, 4))
	case 4:
		_, e = ioReadFull(conn, make([]byte, 16))
	case 3:
		var l [1]byte
		_, e = ioReadFull(conn, l[:])
		if e == nil {
			_, e = ioReadFull(conn, make([]byte, int(l[0])))
		}
	default:
		e = errors.New("invalid SOCKS response")
	}
	if e != nil {
		return fail(e)
	}
	_, e = ioReadFull(conn, make([]byte, 2))
	if e != nil {
		return fail(e)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
func ioReadFull(r net.Conn, b []byte) (int, error) { return io.ReadFull(r, b) }
func (c *Controller) dialActive(ctx context.Context, network, address string) (net.Conn, error) {
	p := c.active.Load()
	if p == nil {
		return nil, errors.New("no healthy VPN profile")
	}
	p.mu.Lock()
	healthy := p.Healthy
	p.mu.Unlock()
	if !healthy {
		return nil, errors.New("active VPN profile is unhealthy")
	}
	return c.socksDial(ctx, p, address)
}

type healthResult struct {
	Healthy     bool
	TransportOK bool
	Reason      string
	Latency     time.Duration
}

func (c *Controller) check(ctx context.Context, p *Profile) healthResult {
	started := time.Now()
	p.mu.Lock()
	session := p.session
	p.mu.Unlock()
	if session == nil {
		return healthResult{Reason: "engine_not_running", Latency: time.Since(started)}
	}
	if err := c.socksHandshake(ctx, session.SOCKSAddr()); err != nil {
		return healthResult{Reason: "socks_unavailable", Latency: time.Since(started)}
	}
	result := healthResult{TransportOK: true, Reason: "https_check_failed"}
	successes := 0
	var lastReason string
	transport := &http.Transport{DialContext: func(x context.Context, n, a string) (net.Conn, error) {
		return c.socksDialAt(x, session.SOCKSAddr(), a)
	}, TLSHandshakeTimeout: c.settings.Failover.CheckTimeout, ResponseHeaderTimeout: c.settings.Failover.CheckTimeout, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: c.settings.Failover.CheckTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, endpoint := range c.settings.Health.URLs {
		if err := ctx.Err(); err != nil {
			lastReason = "timeout"
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			lastReason = "invalid_health_url"
			continue
		}
		r, err := client.Do(req)
		if err != nil {
			lastReason = classifyHealthError(err)
			continue
		}
		status := r.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		_ = r.Body.Close()
		// Any valid HTTP response proves that DNS, TCP, TLS, and the protected route
		// worked. Application errors (403/429/5xx) are not VPN transport failures.
		if healthHTTPStatusReachable(status) {
			successes++
		} else {
			lastReason = fmt.Sprintf("http_%d", status)
		}
		if successes >= c.settings.Health.RequiredSuccesses {
			result.Healthy = true
			result.Reason = ""
			break
		}
	}
	if !result.Healthy && lastReason != "" {
		result.Reason = lastReason
	}
	result.Latency = time.Since(started)
	return result
}

func healthHTTPStatusReachable(status int) bool { return status >= 100 && status <= 599 }

func classifyHealthError(err error) string {
	var dnsErr *net.DNSError
	var netErr net.Error
	var urlErr *url.Error
	switch {
	case errors.As(err, &dnsErr):
		return "dns_error"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &urlErr) && strings.Contains(strings.ToLower(urlErr.Err.Error()), "tls"):
		return "tls_error"
	default:
		return "connect_error"
	}
}

func (c *Controller) socksHandshake(ctx context.Context, addr string) error {
	d := net.Dialer{Timeout: c.settings.Failover.CheckTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.settings.Failover.CheckTimeout))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var response [2]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response != [2]byte{5, 0} {
		return errors.New("SOCKS method negotiation failed")
	}
	return nil
}

func (c *Controller) monitor(ctx context.Context) {
	ticker := time.NewTicker(c.settings.Failover.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		active := c.active.Load()
		sem := make(chan struct{}, c.maxEngines)
		var checks sync.WaitGroup
		for _, p := range c.profiles {
			p.mu.Lock()
			_, running := p.session, p.session != nil
			lastCheck := p.LastCheck
			p.mu.Unlock()
			if !running {
				continue
			}
			if active != nil && p.Priority < active.Priority && time.Since(lastCheck) < c.settings.Failover.RecoveryInterval {
				continue
			}
			checks.Add(1)
			go func(profile *Profile) {
				defer checks.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				pc, cancel := context.WithTimeout(ctx, c.settings.Failover.CheckTimeout)
				result := c.check(pc, profile)
				cancel()
				c.recordHealth(profile, result)
			}(p)
		}
		checks.Wait()
		c.selectProfile()
	}
}

func (c *Controller) recordHealth(p *Profile, result healthResult) {
	p.mu.Lock()
	p.LastCheck = time.Now()
	p.HealthLatencyMS = result.Latency.Milliseconds()
	if result.Healthy {
		p.Successes++
		p.Failures = 0
		p.LastSuccess = p.LastCheck
		if p.Successes >= c.settings.Failover.RecoveryThreshold || p.Healthy {
			p.Healthy = true
			p.State = "HEALTHY"
			p.LastError = ""
			p.restartTimes = nil
		} else {
			p.State = "CONNECTING"
		}
	} else {
		p.Failures++
		p.Successes = 0
		if p.Failures >= c.settings.Failover.FailureThreshold {
			p.Healthy = false
			p.State = "UNHEALTHY"
			p.LastError = result.Reason
		} else if p.Healthy {
			p.State = "DEGRADED"
			p.LastError = result.Reason
		}
		if !result.TransportOK && p.Failures >= c.settings.Failover.FailureThreshold {
			select {
			case p.restartReq <- struct{}{}:
			default:
			}
		}
	}
	p.mu.Unlock()
}
func (c *Controller) selectProfile() {
	c.mu.Lock()
	defer c.mu.Unlock()
	var candidate *Profile
	for _, p := range c.profiles {
		p.mu.Lock()
		healthy := p.Healthy
		p.mu.Unlock()
		if healthy {
			candidate = p
			break
		}
	}
	old := c.active.Load()
	if candidate == old {
		return
	}
	if !c.settings.Failover.Enabled && old != nil {
		return
	}
	if old != nil {
		old.mu.Lock()
		oldHealthy := old.Healthy
		old.mu.Unlock()
		// Never allow cooldown to postpone an emergency failover from an unhealthy active route.
		if oldHealthy && candidate != nil && time.Since(c.lastSwitch) < c.settings.Failover.SwitchCooldown {
			return
		}
	}
	c.active.Store(candidate)
	c.lastSwitch = time.Now()
	c.switches.Add(1)
	from, to := "none", "none"
	if old != nil {
		from = old.Name
	}
	if candidate != nil {
		to = candidate.Name
	}
	slog.Info("profile switched", "from", from, "to", to)
}

func (c *Controller) snapshot() Snapshot {
	active := c.active.Load()
	name := ""
	if active != nil {
		name = active.Name
	}
	profiles := make([]*Profile, 0, len(c.profiles))
	for _, p := range c.profiles {
		p.mu.Lock()
		copy := &Profile{Name: p.Name, ID: p.ID, Priority: p.Priority, State: p.State, Healthy: p.Healthy, LastError: p.LastError, LastCheck: p.LastCheck, LastSuccess: p.LastSuccess, HealthLatencyMS: p.HealthLatencyMS, Failures: p.Failures, Successes: p.Successes, Restarts: p.Restarts}
		p.mu.Unlock()
		profiles = append(profiles, copy)
	}
	return Snapshot{Active: name, Profiles: profiles, Since: c.started, Switches: c.switches.Load()}
}
func (c *Controller) proxyHandler() http.Handler {
	if c.requests == nil {
		c.requests = make(chan struct{}, 512)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case c.requests <- struct{}{}:
			defer func() { <-c.requests }()
		case <-r.Context().Done():
			return
		default:
			http.Error(w, "proxy connection limit reached", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodConnect {
			conn, e := c.dialActive(r.Context(), "tcp", r.Host)
			if e != nil {
				http.Error(w, "VPN unavailable", http.StatusServiceUnavailable)
				return
			}
			h, ok := w.(http.Hijacker)
			if !ok {
				conn.Close()
				http.Error(w, "CONNECT unsupported", 500)
				return
			}
			client, rw, e := h.Hijack()
			if e != nil {
				conn.Close()
				return
			}
			_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = rw.Flush()
			go proxyCopy(conn, client)
			proxyCopy(client, conn)
			_ = client.Close()
			_ = conn.Close()
			return
		}
		if r.URL.Scheme != "http" || r.URL.Host == "" {
			http.Error(w, "absolute-form HTTP URL required", http.StatusBadRequest)
			return
		}
		p := c.active.Load()
		if p == nil {
			http.Error(w, "no healthy VPN profile", http.StatusServiceUnavailable)
			return
		}
		p.mu.Lock()
		healthy, tr := p.Healthy, p.transport
		p.mu.Unlock()
		if !healthy || tr == nil {
			http.Error(w, "active VPN profile is unhealthy", http.StatusServiceUnavailable)
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Header = out.Header.Clone()
		out.Header.Del("Proxy-Authorization")
		out.Header.Del("Proxy-Connection")
		resp, e := tr.RoundTrip(out)
		if e != nil {
			http.Error(w, "VPN upstream unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			if isHopByHopHeader(k, resp.Header) {
				continue
			}
			for _, x := range v {
				w.Header().Add(k, x)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func applicationHandler(c *Controller) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		active := c.active.Load()
		if active == nil {
			http.Error(w, "no healthy VPN", http.StatusServiceUnavailable)
			return
		}
		active.mu.Lock()
		healthy := active.Healthy
		active.mu.Unlock()
		if !healthy {
			http.Error(w, "no healthy VPN", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(c.snapshot()) })
	mux.HandleFunc("/api/profiles", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(c.snapshot().Profiles) })
	mux.HandleFunc("/api/active", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"active": c.snapshot().Active})
	})
	proxy := c.proxyHandler()
	mux.Handle("/", proxy)
	// CONNECT uses authority-form and ServeMux may not resolve it as a slash path.
	// Route it explicitly to the proxy handler rather than letting the mux return 404.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			proxy.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func isHopByHopHeader(key string, header http.Header) bool {
	switch strings.ToLower(key) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	for _, v := range header.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), key) {
				return true
			}
		}
	}
	return false
}
func proxyCopy(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		settings, err := loadSettings()
		if err != nil {
			os.Exit(1)
		}
		client := http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", settings.Proxy.HTTPPort))
		if err != nil {
			os.Exit(1)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			os.Exit(1)
		}
		return
	}
	s, e := loadSettings()
	if e != nil {
		slog.Error("settings", "error", e)
		os.Exit(1)
	}
	ps, e := discover(s)
	if e != nil {
		slog.Error("profiles", "error", e)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	c := &Controller{profiles: ps, settings: s, started: time.Now()}
	c.start(ctx)
	srv := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", s.Proxy.HTTPPort), Handler: applicationHandler(c), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
		}
	}()
	slog.Info("listening", "address", srv.Addr, "profiles", len(ps))
	serverErr := srv.ListenAndServe()
	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		slog.Error("http server", "error", serverErr)
	}
	cancel()
	c.wg.Wait()
	for i, p := range c.profiles {
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
		if i < c.maxEngines {
			_ = os.Remove(filepath.Join(c.runtimeDir, fmt.Sprintf("profile-%d.conf", i)))
		}
	}
	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		os.Exit(1)
	}
}

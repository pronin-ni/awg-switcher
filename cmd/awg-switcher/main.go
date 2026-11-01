package main

import (
	"context"
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
	ExternalIP      string    `json:"external_ip,omitempty"`
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
	slot            int
	enabled         bool
	cancel          context.CancelFunc
	done            chan struct{}
	configRevision  uint64
}
type Snapshot struct {
	Active            string            `json:"active,omitempty"`
	Profiles          []*Profile        `json:"profiles"`
	Since             time.Time         `json:"since"`
	Switches          uint64            `json:"switches"`
	LastSwitch        time.Time         `json:"last_switch,omitempty"`
	ManualUntil       time.Time         `json:"manual_until,omitempty"`
	ActiveConnections int64             `json:"active_connections"`
	Events            []ControllerEvent `json:"events"`
}
type ControllerEvent struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Profile string    `json:"profile,omitempty"`
	Message string    `json:"message"`
}
type Controller struct {
	profiles          []*Profile
	profilesMu        sync.RWMutex
	dynamicMu         sync.Mutex
	active            atomic.Pointer[Profile]
	settings          Settings
	started           time.Time
	switches          atomic.Uint64
	mu                sync.Mutex
	lastSwitch        time.Time
	engine            Engine
	runtimeDir        string
	maxEngines        int
	requests          chan struct{}
	wg                sync.WaitGroup
	ctx               context.Context
	manualUntil       time.Time
	eventsMu          sync.Mutex
	events            []ControllerEvent
	onEvent           func()
	activeConnections atomic.Int64
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
		s.Health.URLs = []string{"https://api.ipify.org", "https://www.cloudflare.com/cdn-cgi/trace"}
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
	dataDir := os.Getenv("AWG_DATA_DIR")
	if dataDir == "" {
		dataDir = "/app/data"
	}
	dirs := []string{s.Profiles.Directory, filepath.Join(dataDir, "profiles")}
	ranks := map[string]int{}
	for i, n := range s.Profiles.Priority {
		ranks[n] = i
	}
	if s.Profiles.Primary != "" {
		ranks[s.Profiles.Primary] = -1
	}
	var ps []*Profile
	seen := map[string]bool{}
	for dirIndex, rawDir := range dirs {
		dir, e := filepath.Abs(rawDir)
		if e != nil {
			continue
		}
		entries, e := os.ReadDir(dir)
		if e != nil {
			continue
		}
		for _, entry := range entries {
			n := entry.Name()
			if !strings.HasSuffix(strings.ToLower(n), ".conf") {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !entry.Type().IsRegular() {
				slog.Warn("profile ignored", "profile", n, "reason", "not a regular file")
				continue
			}
			p := filepath.Join(dir, n)
			b, e := os.ReadFile(p)
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
			id := n
			if dirIndex == 1 {
				id = strings.TrimSuffix(n, filepath.Ext(n))
			}
			rank, ok := ranks[n]
			if !ok {
				rank = 1000
			}
			ps = append(ps, &Profile{Name: strings.TrimSuffix(n, filepath.Ext(n)), ID: id, Priority: rank, State: "STARTING", path: p, config: norm, restartReq: make(chan struct{}, 1)})
		}
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Priority == ps[j].Priority {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].Priority < ps[j].Priority
	})
	return ps, nil
}

func (c *Controller) start(ctx context.Context) {
	c.ctx = ctx
	if c.runtimeDir == "" {
		c.runtimeDir = "/run/awg-switcher"
	}
	if c.engine == nil {
		c.engine = ProcessEngine{Binary: "/usr/local/bin/wireproxy", RuntimeDir: c.runtimeDir}
	}
	if c.maxEngines <= 0 {
		c.maxEngines = 64
	}
	if c.requests == nil {
		c.requests = make(chan struct{}, 512)
	}
	if err := os.MkdirAll(c.runtimeDir, 0700); err != nil {
		slog.Error("runtime directory unavailable", "error", err)
	}
	for i, p := range c.profilesSnapshot() {
		c.prepareProfile(p)
		if i >= c.maxEngines {
			p.mu.Lock()
			p.enabled = false
			p.State = "DISABLED"
			p.LastError = "profile concurrency limit reached"
			p.mu.Unlock()
			continue
		}
		c.launchProfile(p)
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.monitor(ctx)
	}()
}

func stableSlot(id string) int {
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		h = (h ^ uint32(id[i])) * 16777619
	}
	return int(h & 0x7fffffff)
}
func (c *Controller) prepareProfile(p *Profile) {
	if p.ID == "" {
		p.ID = p.Name
	}
	profiles := c.profilesSnapshot()
	base := stableSlot(p.ID)
	used := map[string]bool{}
	for _, other := range profiles {
		if other == p {
			continue
		}
		other.mu.Lock()
		if other.socks != "" {
			used[other.socks] = true
		}
		other.mu.Unlock()
	}
	for offset := 0; offset < 40000; offset++ {
		p.slot = (base + offset) % 40000
		candidate := fmt.Sprintf("127.0.0.1:%d", 22000+p.slot)
		if !used[candidate] {
			break
		}
	}
	port := 22000 + p.slot
	p.socks = fmt.Sprintf("127.0.0.1:%d", port)
	if p.State != "DISABLED" {
		p.enabled = true
	}
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
}
func (c *Controller) launchProfile(p *Profile) {
	p.mu.Lock()
	if !p.enabled || p.cancel != nil {
		p.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(c.ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	done := p.done
	slot := p.slot
	p.mu.Unlock()
	c.wg.Add(1)
	go func() { defer close(done); c.supervise(ctx, p, slot) }()
}
func (c *Controller) profilesSnapshot() []*Profile {
	c.profilesMu.RLock()
	defer c.profilesMu.RUnlock()
	return append([]*Profile(nil), c.profiles...)
}
func (c *Controller) addRuntimeProfile(id, name string, config []byte, path string) (*Profile, error) {
	c.dynamicMu.Lock()
	defer c.dynamicMu.Unlock()
	if c.maxEngines > 0 && len(c.profilesSnapshot()) >= c.maxEngines {
		return nil, errors.New("profile limit reached")
	}
	priority := 0
	c.profilesMu.Lock()
	for _, x := range c.profiles {
		if x.ID == id {
			c.profilesMu.Unlock()
			return nil, errors.New("profile already exists")
		}
		x.mu.Lock()
		if x.Priority >= priority {
			priority = x.Priority + 1
		}
		x.mu.Unlock()
	}
	c.profilesMu.Unlock()
	p := &Profile{Name: name, ID: id, Priority: priority, State: "STARTING", path: path, config: append([]byte(nil), config...), restartReq: make(chan struct{}, 1), enabled: true}
	c.prepareProfile(p)
	c.profilesMu.Lock()
	c.profiles = append(c.profiles, p)
	c.profilesMu.Unlock()
	c.launchProfile(p)
	return p, nil
}
func (c *Controller) findProfile(id string) *Profile {
	for _, p := range c.profilesSnapshot() {
		if p.ID == id {
			return p
		}
	}
	return nil
}
func (c *Controller) sortProfiles() {
	c.profilesMu.Lock()
	sort.SliceStable(c.profiles, func(i, j int) bool {
		c.profiles[i].mu.Lock()
		pi := c.profiles[i].Priority
		c.profiles[i].mu.Unlock()
		c.profiles[j].mu.Lock()
		pj := c.profiles[j].Priority
		c.profiles[j].mu.Unlock()
		if pi == pj {
			return c.profiles[i].ID < c.profiles[j].ID
		}
		return pi < pj
	})
	c.profilesMu.Unlock()
	c.selectProfile()
}

// setProfilePriority reorders the selected profile relative to its current
// peers, then stores a unique, contiguous priority sequence. This avoids ties
// when the UI moves a profile up/down and makes startup order deterministic.
func (c *Controller) setProfilePriority(id string, priority int) error {
	c.dynamicMu.Lock()
	defer c.dynamicMu.Unlock()
	c.profilesMu.Lock()
	target := -1
	for i, p := range c.profiles {
		if p.ID == id {
			target = i
			break
		}
	}
	if target < 0 {
		c.profilesMu.Unlock()
		return errors.New("profile not found")
	}
	p := c.profiles[target]
	c.profiles = append(c.profiles[:target], c.profiles[target+1:]...)
	if priority < 0 {
		priority = 0
	}
	if priority > len(c.profiles) {
		priority = len(c.profiles)
	}
	c.profiles = append(c.profiles, nil)
	copy(c.profiles[priority+1:], c.profiles[priority:])
	c.profiles[priority] = p
	for i, p := range c.profiles {
		p.mu.Lock()
		p.Priority = i
		p.mu.Unlock()
	}
	c.profilesMu.Unlock()
	c.selectProfile()
	return nil
}
func (c *Controller) setProfileEnabled(id string, enabled bool) error {
	c.dynamicMu.Lock()
	defer c.dynamicMu.Unlock()
	p := c.findProfile(id)
	if p == nil {
		return errors.New("profile not found")
	}
	p.mu.Lock()
	if p.enabled == enabled {
		p.mu.Unlock()
		return nil
	}
	p.enabled = enabled
	cancel, done := p.cancel, p.done
	if !enabled {
		p.Healthy = false
		p.State = "DISABLED"
		p.LastError = ""
	}
	p.mu.Unlock()
	if enabled {
		c.launchProfile(p)
		return nil
	}
	c.selectProfile()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return errors.New("profile supervisor did not stop")
		}
	}
	p.mu.Lock()
	p.cancel = nil
	p.session = nil
	p.mu.Unlock()
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	c.selectProfile()
	return nil
}
func (c *Controller) selectManual(id string, forDuration time.Duration) error {
	p := c.findProfile(id)
	if p == nil {
		return errors.New("profile not found")
	}
	p.mu.Lock()
	healthy := p.Healthy && p.enabled
	p.mu.Unlock()
	if !healthy {
		return errors.New("profile is not healthy")
	}
	c.mu.Lock()
	c.manualUntil = time.Now().Add(forDuration)
	c.active.Store(p)
	c.lastSwitch = time.Now()
	c.switches.Add(1)
	c.mu.Unlock()
	c.appendEvent(ControllerEvent{At: time.Now().UTC(), Kind: "manual_switch", Profile: p.ID, Message: "manual profile override"})
	return nil
}
func (c *Controller) clearManual() {
	c.mu.Lock()
	c.manualUntil = time.Time{}
	c.lastSwitch = time.Time{}
	c.mu.Unlock()
	c.selectProfile()
}
func (c *Controller) removeRuntimeProfile(id string) error {
	c.dynamicMu.Lock()
	defer c.dynamicMu.Unlock()
	p := c.findProfile(id)
	if p == nil {
		return errors.New("profile not found")
	}
	// Mark unavailable and choose the failover route before stopping the engine.
	p.mu.Lock()
	p.Healthy = false
	p.State = "DISABLED"
	p.enabled = false
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	c.selectProfile()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return errors.New("profile supervisor did not stop")
		}
	}
	c.profilesMu.Lock()
	for i, x := range c.profiles {
		if x == p {
			c.profiles = append(c.profiles[:i], c.profiles[i+1:]...)
			break
		}
	}
	for i, x := range c.profiles {
		x.mu.Lock()
		x.Priority = i
		x.mu.Unlock()
	}
	c.profilesMu.Unlock()
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	c.selectProfile()
	return nil
}
func (c *Controller) replaceRuntimeConfig(id string, config []byte) error {
	c.dynamicMu.Lock()
	defer c.dynamicMu.Unlock()
	p := c.findProfile(id)
	if p == nil {
		return errors.New("profile not found")
	}
	p.mu.Lock()
	p.config = append([]byte(nil), config...)
	p.configRevision++
	wasActive := c.active.Load() == p
	p.Healthy = false
	p.Successes = 0
	p.Failures = 0
	p.State = "CONNECTING"
	p.LastError = "configuration replaced"
	restart := p.restartReq
	p.mu.Unlock()
	if wasActive {
		c.selectProfile()
	}
	select {
	case restart <- struct{}{}:
	default:
	}
	c.appendEvent(ControllerEvent{At: time.Now().UTC(), Kind: "profile_replaced", Profile: id, Message: "profile configuration replaced; engine restart requested"})
	return nil
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
	if _, e = ioReadFull(conn, head[:]); e != nil {
		return fail(errors.New("SOCKS connect response unavailable"))
	}
	if head[1] != 0 {
		return fail(fmt.Errorf("SOCKS connect rejected with reply %d", head[1]))
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
	ExternalIP  string
	Revision    uint64
}

func (c *Controller) check(ctx context.Context, p *Profile) healthResult {
	started := time.Now()
	p.mu.Lock()
	session := p.session
	revision := p.configRevision
	p.mu.Unlock()
	if session == nil {
		return healthResult{Reason: "engine_not_running", Latency: time.Since(started), Revision: revision}
	}
	if err := c.socksHandshake(ctx, session.SOCKSAddr()); err != nil {
		return healthResult{Reason: "socks_unavailable", Latency: time.Since(started), Revision: revision}
	}
	result := healthResult{TransportOK: true, Reason: "https_check_failed", Revision: revision}
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
		body, _ := io.ReadAll(io.LimitReader(r.Body, 256))
		_ = r.Body.Close()
		if parsed, _ := url.Parse(endpoint); parsed != nil && parsed.Hostname() == "api.ipify.org" {
			if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil {
				result.ExternalIP = ip.String()
			}
		}
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

func (c *Controller) checkURL(ctx context.Context, p *Profile, rawURL string) map[string]any {
	started := time.Now()
	parsedURL, _ := url.Parse(rawURL)
	result := map[string]any{"profile_id": p.ID, "hostname": parsedURL.Hostname(), "dns": "delegated_to_socks5", "socks5": "not_checked", "tls": "not_checked", "http_status": 0}
	p.mu.Lock()
	session := p.session
	healthy := p.Healthy
	p.mu.Unlock()
	if session == nil || !healthy {
		result["error_type"] = "profile_unavailable"
		result["error"] = "selected profile is not healthy"
		result["duration_ms"] = time.Since(started).Milliseconds()
		return result
	}
	probeCtx, cancel := context.WithTimeout(ctx, c.settings.Failover.CheckTimeout)
	defer cancel()
	if err := c.socksHandshake(probeCtx, session.SOCKSAddr()); err != nil {
		result["socks5"] = "listener_unavailable"
		result["error_type"] = "socks_listener_unavailable"
		result["error"] = "profile SOCKS5 listener is unavailable"
		result["duration_ms"] = time.Since(started).Milliseconds()
		return result
	}
	result["socks5"] = "negotiated"
	transport := &http.Transport{DialContext: func(x context.Context, n, a string) (net.Conn, error) {
		conn, err := c.socksDialAt(x, session.SOCKSAddr(), a)
		if err == nil {
			result["socks5"] = "connected"
		} else {
			result["socks5"] = "connect_rejected"
			result["error_type"] = classifyHealthError(err)
		}
		return conn, err
	}, TLSHandshakeTimeout: c.settings.Failover.CheckTimeout, ResponseHeaderTimeout: c.settings.Failover.CheckTimeout, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: c.settings.Failover.CheckTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, rawURL, nil)
	if err == nil {
		var response *http.Response
		response, err = client.Do(req)
		if response != nil {
			result["http_status"] = response.StatusCode
			if response.TLS != nil {
				result["tls"] = "verified"
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
		}
	}
	if err != nil {
		errorType, _ := result["error_type"].(string)
		if errorType == "" || errorType == "none" {
			errorType = classifyHealthError(err)
		}
		result["error_type"] = errorType
		result["error"] = "HTTPS probe failed: " + errorType
	} else {
		result["error_type"] = "none"
		result["error"] = ""
	}
	result["duration_ms"] = time.Since(started).Milliseconds()
	return result
}

func healthHTTPStatusReachable(status int) bool { return status >= 100 && status <= 599 }

func classifyHealthError(err error) string {
	var dnsErr *net.DNSError
	var netErr net.Error
	var urlErr *url.Error
	switch {
	case strings.Contains(strings.ToLower(err.Error()), "socks connect rejected with reply 2"):
		return "socks_policy_rejected"
	case strings.Contains(strings.ToLower(err.Error()), "socks connect rejected with reply 3"):
		return "socks_network_unreachable"
	case strings.Contains(strings.ToLower(err.Error()), "socks connect rejected with reply 4"):
		return "socks_host_unreachable"
	case strings.Contains(strings.ToLower(err.Error()), "socks connect rejected with reply 5"):
		return "socks_connection_refused"
	case strings.Contains(strings.ToLower(err.Error()), "socks connect rejected"):
		return "socks_target_rejected"
	case strings.Contains(strings.ToLower(err.Error()), "socks negotiation failed"):
		return "socks_protocol_error"
	case errors.As(err, &dnsErr):
		return "dns_error"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &urlErr) && (strings.Contains(strings.ToLower(urlErr.Err.Error()), "tls") || strings.Contains(strings.ToLower(urlErr.Err.Error()), "certificate")):
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
		for _, p := range c.profilesSnapshot() {
			p.mu.Lock()
			_, running := p.session, p.session != nil && p.enabled
			lastCheck := p.LastCheck
			p.mu.Unlock()
			if !running {
				continue
			}
			if active != nil {
				active.mu.Lock()
				activePriority := active.Priority
				active.mu.Unlock()
				p.mu.Lock()
				priority := p.Priority
				p.mu.Unlock()
				if priority < activePriority && time.Since(lastCheck) < c.settings.Failover.RecoveryInterval {
					continue
				}
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
	if result.Revision != p.configRevision {
		p.mu.Unlock()
		return
	}
	if !p.enabled {
		p.mu.Unlock()
		return
	}
	wasHealthy := p.Healthy
	p.LastCheck = time.Now()
	if result.ExternalIP != "" {
		p.ExternalIP = result.ExternalIP
	}
	p.HealthLatencyMS = result.Latency.Milliseconds()
	if result.Healthy {
		p.Successes++
		p.Failures = 0
		p.LastSuccess = p.LastCheck
		if p.Successes >= c.settings.Failover.RecoveryThreshold || p.Healthy {
			p.Healthy = true
			p.State = "HEALTHY"
			p.LastError = ""
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
		p.LastError = result.Reason
		if !result.TransportOK && p.Failures >= c.settings.Failover.FailureThreshold {
			select {
			case p.restartReq <- struct{}{}:
			default:
			}
		}
	}
	p.mu.Unlock()
	if !result.Healthy && !wasHealthy {
		c.appendEvent(ControllerEvent{At: time.Now().UTC(), Kind: "profile_error", Profile: p.ID, Message: result.Reason})
	}
}
func (c *Controller) selectProfile() {
	c.mu.Lock()
	defer c.mu.Unlock()
	var candidate *Profile
	profiles := c.profilesSnapshot()
	sort.SliceStable(profiles, func(i, j int) bool {
		profiles[i].mu.Lock()
		pi := profiles[i].Priority
		profiles[i].mu.Unlock()
		profiles[j].mu.Lock()
		pj := profiles[j].Priority
		profiles[j].mu.Unlock()
		return pi < pj
	})
	if !c.manualUntil.IsZero() && time.Now().Before(c.manualUntil) {
		manual := c.active.Load()
		if manual != nil {
			manual.mu.Lock()
			healthy := manual.Healthy && manual.enabled
			manual.mu.Unlock()
			if healthy {
				return
			}
		}
		c.manualUntil = time.Time{}
	}
	for _, p := range profiles {
		p.mu.Lock()
		healthy := p.Healthy && p.enabled
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
	c.appendEvent(ControllerEvent{At: time.Now().UTC(), Kind: "switch", Profile: to, Message: from + " → " + to})
}

func (c *Controller) appendEvent(event ControllerEvent) {
	c.eventsMu.Lock()
	c.events = append(c.events, event)
	if len(c.events) > 200 {
		c.events = append([]ControllerEvent(nil), c.events[len(c.events)-200:]...)
	}
	c.eventsMu.Unlock()
	if c.onEvent != nil {
		c.onEvent()
	}
}

func (c *Controller) snapshot() Snapshot {
	c.mu.Lock()
	lastSwitch := c.lastSwitch
	c.mu.Unlock()
	active := c.active.Load()
	activeID := ""
	if active != nil {
		active.mu.Lock()
		activeID = active.ID
		active.mu.Unlock()
	}
	profiles := make([]*Profile, 0, len(c.profilesSnapshot()))
	for _, p := range c.profilesSnapshot() {
		p.mu.Lock()
		copy := &Profile{Name: p.Name, ID: p.ID, Priority: p.Priority, State: p.State, Healthy: p.Healthy, LastError: p.LastError, LastCheck: p.LastCheck, LastSuccess: p.LastSuccess, HealthLatencyMS: p.HealthLatencyMS, ExternalIP: p.ExternalIP, Failures: p.Failures, Successes: p.Successes, Restarts: p.Restarts}
		p.mu.Unlock()
		profiles = append(profiles, copy)
	}
	c.eventsMu.Lock()
	events := append([]ControllerEvent(nil), c.events...)
	c.eventsMu.Unlock()
	c.mu.Lock()
	manualUntil := c.manualUntil
	c.mu.Unlock()
	return Snapshot{Active: activeID, Profiles: profiles, Since: c.started, Switches: c.switches.Load(), LastSwitch: lastSwitch, ManualUntil: manualUntil, ActiveConnections: c.activeConnections.Load(), Events: events}
}
func (c *Controller) proxyHandler() http.Handler {
	if c.requests == nil {
		c.requests = make(chan struct{}, 512)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.activeConnections.Add(1)
		defer c.activeConnections.Add(-1)
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
				if strings.Contains(e.Error(), "no healthy VPN") || strings.Contains(e.Error(), "profile is unhealthy") {
					http.Error(w, "no healthy VPN profile", http.StatusServiceUnavailable)
				} else {
					http.Error(w, "VPN transport failed: "+classifyHealthError(e), http.StatusBadGateway)
				}
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
			http.Error(w, "VPN transport failed: "+classifyHealthError(e), http.StatusBadGateway)
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

// prepareDataDir handles a fresh Docker bind mount without requiring the NAS
// user to chown it. The container starts with only the three capabilities
// needed to transfer ownership, then permanently drops to the application UID.
func prepareDataDir(dir string) error {
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create data directory: %w", err)
		}
		if err := os.Chown(dir, 10001, 10001); err != nil {
			return fmt.Errorf("initialize data directory ownership: %w", err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("secure data directory: %w", err)
		}
		if err := syscall.Setgroups([]int{10001}); err != nil {
			return fmt.Errorf("drop supplementary groups: %w", err)
		}
		if err := syscall.Setgid(10001); err != nil {
			return fmt.Errorf("drop group privileges: %w", err)
		}
		if err := syscall.Setuid(10001); err != nil {
			return fmt.Errorf("drop user privileges: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	return nil
}

func main() {
	dataDir := os.Getenv("AWG_DATA_DIR")
	if dataDir == "" {
		dataDir = "/app/data"
	}
	if len(os.Args) == 2 && os.Args[1] == "create-admin" {
		if err := prepareDataDir(dataDir); err != nil {
			slog.Error("data directory initialization failed", "error", err)
			os.Exit(1)
		}
		if err := adminPasswordCLI(dataDir); err != nil {
			slog.Error("administrator initialization failed", "error", err)
			os.Exit(1)
		}
		_ = os.Remove(bootstrapPath(dataDir))
		fmt.Println("Administrator initialized.")
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		settings, err := loadSettings()
		if err != nil {
			os.Exit(1)
		}
		client := http.Client{Timeout: 3 * time.Second}
		// Container health means the control plane is alive. An empty install or
		// failed VPN remains a healthy app process while the proxy itself fails closed.
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", settings.Proxy.HTTPPort))
		if err != nil {
			os.Exit(1)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			os.Exit(1)
		}
		return
	}
	if err := prepareDataDir(dataDir); err != nil {
		slog.Error("data directory initialization failed", "error", err)
		os.Exit(1)
	}
	bootstrap, err := ensureBootstrapToken(dataDir)
	if err != nil {
		slog.Error("first-run setup initialization failed", "error", err)
		os.Exit(1)
	}
	if bootstrap != "" {
		slog.Warn("first administrator setup is required; enter this one-time code in the Web UI", "setup_code", bootstrap)
	}
	s, e := loadSettings()
	if e != nil {
		slog.Error("settings", "error", e)
		os.Exit(1)
	}
	ps, e := discover(s)
	if e != nil {
		slog.Error("profile discovery", "error", e)
		ps = []*Profile{}
	}
	if err := loadProfileState(dataDir, ps); err != nil {
		slog.Error("profile state", "error", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	c := &Controller{profiles: ps, settings: s, started: time.Now()}
	adminAddr := os.Getenv("AWG_ADMIN_LISTEN")
	if adminAddr == "" {
		adminAddr = "0.0.0.0:8080"
	}
	admin := &webServer{controller: c, dataDir: dataDir, sessions: map[string]webSession{}}
	if events, err := loadStateEvents(dataDir); err != nil {
		slog.Error("event history", "error", err)
	} else {
		c.events = events
	}
	c.onEvent = func() {
		if err := admin.persistState(); err != nil {
			slog.Error("persistent state update failed")
		}
	}
	c.start(ctx)
	proxySrv := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", s.Proxy.HTTPPort), Handler: applicationHandler(c), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	adminSrv := &http.Server{Addr: adminAddr, Handler: admin.handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		_ = proxySrv.Shutdown(shutdownCtx)
		_ = adminSrv.Shutdown(shutdownCtx)
	}()
	serverErrs := make(chan error, 2)
	go func() { serverErrs <- proxySrv.ListenAndServe() }()
	go func() { serverErrs <- adminSrv.ListenAndServe() }()
	slog.Info("listeners started", "proxy", proxySrv.Addr, "admin", adminSrv.Addr, "profiles", len(ps))
	serverErr := <-serverErrs
	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		slog.Error("http server", "error", serverErr)
	}
	cancel()
	c.wg.Wait()
	if err := admin.persistState(); err != nil {
		slog.Error("final state persistence failed")
	}
	for _, p := range c.profilesSnapshot() {
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
		_ = os.Remove(filepath.Join(c.runtimeDir, fmt.Sprintf("profile-%08x.conf", uint32(p.slot))))
	}
	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		os.Exit(1)
	}
}

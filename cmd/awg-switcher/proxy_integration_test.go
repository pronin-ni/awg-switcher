package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testSocks struct {
	listener     net.Listener
	target       string
	connectDelay time.Duration
	accepts      atomic.Int32
	hosts        chan string
	closed       chan struct{}
	wg           sync.WaitGroup
	mu           sync.Mutex
	connections  map[net.Conn]struct{}
	available    atomic.Bool
	closeOnce    sync.Once
}

func newTestSocks(t *testing.T, target string) *testSocks {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSocks{listener: l, target: target, hosts: make(chan string, 128), closed: make(chan struct{}), connections: make(map[net.Conn]struct{})}
	s.available.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			s.mu.Lock()
			s.connections[c] = struct{}{}
			s.mu.Unlock()
			s.accepts.Add(1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
				s.handle(c)
			}()
		}
	}()
	t.Cleanup(func() { s.Close(); s.wg.Wait() })
	return s
}

func (s *testSocks) Addr() string { return s.listener.Addr().String() }
func (s *testSocks) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.listener.Close()
		s.mu.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.mu.Unlock()
	})
}
func (s *testSocks) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))
	var hello [2]byte
	if _, e := io.ReadFull(client, hello[:]); e != nil {
		return
	}
	if hello[0] != 5 {
		return
	}
	methods := make([]byte, int(hello[1]))
	if _, e := io.ReadFull(client, methods); e != nil {
		return
	}
	if _, e := client.Write([]byte{5, 0}); e != nil {
		return
	}
	var header [4]byte
	if _, e := io.ReadFull(client, header[:]); e != nil {
		return
	}
	host := ""
	switch header[3] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(client, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(client, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		var n [1]byte
		if _, e := io.ReadFull(client, n[:]); e != nil {
			return
		}
		b := make([]byte, int(n[0]))
		if _, e := io.ReadFull(client, b); e != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	var port [2]byte
	if _, e := io.ReadFull(client, port[:]); e != nil {
		return
	}
	if header[1] != 1 {
		return
	}
	select {
	case s.hosts <- host:
	default:
	}
	if !s.available.Load() {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if s.connectDelay > 0 {
		time.Sleep(s.connectDelay)
	}
	upstream, e := net.DialTimeout("tcp", s.target, 2*time.Second)
	if e != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, e = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		_, _ = io.Copy(upstream, client)
		if x, ok := upstream.(*net.TCPConn); ok {
			_ = x.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		defer copies.Done()
		_, _ = io.Copy(client, upstream)
		if x, ok := client.(*net.TCPConn); ok {
			_ = x.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	copies.Wait()
}

type testSession struct {
	addr  string
	done  chan struct{}
	once  sync.Once
	socks *testSocks
}

func (s *testSession) SOCKSAddr() string     { return s.addr }
func (s *testSession) Done() <-chan struct{} { return s.done }
func (s *testSession) Err() error            { return nil }
func (s *testSession) Stop(context.Context) error {
	s.once.Do(func() {
		if s.socks != nil {
			s.socks.Close()
		}
		close(s.done)
	})
	return nil
}

type testEngine struct {
	t        *testing.T
	mu       sync.Mutex
	routes   map[string]string
	sessions map[string]*testSocks
}

func (e *testEngine) Start(_ context.Context, config []byte, _ string, _ int) (EngineSession, error) {
	name := string(config)
	e.mu.Lock()
	target, ok := e.routes[name]
	e.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown synthetic profile")
	}
	socks := newTestSocks(e.t, target)
	e.mu.Lock()
	e.sessions[name] = socks
	e.mu.Unlock()
	return &testSession{addr: socks.Addr(), done: make(chan struct{}), socks: socks}, nil
}

func (e *testEngine) setAvailable(name string, available bool) {
	e.mu.Lock()
	socks := e.sessions[name]
	e.mu.Unlock()
	if socks != nil {
		socks.available.Store(available)
	}
}

func testController(t *testing.T, socksAddr string) *Controller {
	t.Helper()
	settings := Settings{}
	settings.Failover.CheckTimeout = 2 * time.Second
	settings.Failover.Enabled = true
	settings.Failover.FailureThreshold = 2
	settings.Failover.RecoveryThreshold = 1
	settings.Health.RequiredSuccesses = 1
	p := &Profile{Name: "test", ID: "test", Priority: 0, State: "HEALTHY", Healthy: true, enabled: true, socks: socksAddr}
	c := &Controller{profiles: []*Profile{p}, settings: settings, started: time.Now(), requests: make(chan struct{}, 64)}
	p.transport = &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.socksDial(ctx, p, address)
	}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConnsPerHost: 4}
	t.Cleanup(func() { p.transport.CloseIdleConnections() })
	c.active.Store(p)
	return c
}

func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

func TestHTTPProxyMethodsBodiesStreamingAndReuse(t *testing.T) {
	var hits atomic.Int32
	large := strings.Repeat("x", 2<<20)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method == http.MethodHead {
			w.Header().Set("X-Method", r.Method)
			return
		}
		if r.URL.Path == "/large" {
			_, _ = io.WriteString(w, large)
			return
		}
		w.Header().Set("X-Method", r.Method)
		_, _ = io.WriteString(w, string(body))
	}))
	defer origin.Close()
	socks := newTestSocks(t, strings.TrimPrefix(origin.URL, "http://"))
	c := testController(t, socks.Addr())
	proxy := httptest.NewServer(applicationHandler(c))
	defer proxy.Close()
	client := proxyClient(t, proxy.URL)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead} {
		body := strings.NewReader("payload-" + method)
		req, err := http.NewRequest(method, origin.URL+"/method", body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		got := resp.Header.Get("X-Method")
		if got != method {
			t.Errorf("method forwarded=%q want=%q", got, method)
		}
		if method == http.MethodHead {
			resp.Body.Close()
			continue
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "payload-"+method {
			t.Errorf("request body mismatch for %s", method)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/large", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != int64(len(large)) {
		t.Fatalf("stream size=%d err=%v", n, err)
	}
	if hits.Load() != 6 {
		t.Fatalf("origin requests=%d, want 6", hits.Load())
	}
	if socks.accepts.Load() >= hits.Load() {
		t.Fatalf("expected connection reuse, SOCKS sessions=%d requests=%d", socks.accepts.Load(), hits.Load())
	}
	select {
	case host := <-socks.hosts:
		if host == "" {
			t.Fatal("SOCKS did not receive destination hostname")
		}
	default:
		t.Fatal("no SOCKS target was observed")
	}
}

func TestHTTPSConnectUsesSelectedSOCKSRoute(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Via-Origin", "tls")
		_, _ = io.WriteString(w, "secure-response")
	}))
	defer origin.Close()
	socks := newTestSocks(t, strings.TrimPrefix(origin.URL, "https://"))
	// CONNECT must use its independent 30s timeout, not the 8s healthcheck limit.
	socks.connectDelay = 8200 * time.Millisecond
	c := testController(t, socks.Addr())
	proxy := httptest.NewServer(applicationHandler(c))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	originURL, _ := url.Parse(origin.URL)
	root := x509.NewCertPool()
	root.AddCert(origin.Certificate())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: root, ServerName: "example.com"}, DisableKeepAlives: true}
	client := http.Client{Transport: transport, Timeout: 15 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com:"+strconv.Itoa(portOf(originURL.Host))+"/", nil)
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "secure-response" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if elapsed := time.Since(started); elapsed < 8*time.Second {
		t.Fatalf("delayed SOCKS CONNECT completed too soon to exercise timeout boundary: %s", elapsed)
	}
	select {
	case host := <-socks.hosts:
		if host != "example.com" {
			t.Fatalf("CONNECT destination resolved outside SOCKS: %q", host)
		}
	default:
		t.Fatal("CONNECT did not use SOCKS")
	}
}

func TestHealthEndpointsSeparateVPNConnectivityFromServiceFailures(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/service-down" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/forbidden" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	socks := newTestSocks(t, strings.TrimPrefix(origin.URL, "https://"))
	parsed, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	c := testController(t, socks.Addr())
	c.settings.Health.URLs = []string{origin.URL + "/forbidden", origin.URL + "/ok"}
	c.settings.Health.RequiredSuccesses = 1
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.socksDialAt(ctx, socks.Addr(), address)
	}, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: parsed.Hostname()}, DisableKeepAlives: true}
	result := c.checkEndpoints(context.Background(), time.Now(), 0, transport)
	transport.CloseIdleConnections()
	if !result.Healthy || !result.TransportOK || !result.ServiceOK {
		t.Fatalf("a single 403 hid the independent successful service endpoint: %+v", result)
	}
	c.settings.Health.URLs = []string{origin.URL + "/forbidden", origin.URL + "/service-down"}
	transport = &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.socksDialAt(ctx, socks.Addr(), address)
	}, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: parsed.Hostname()}, DisableKeepAlives: true}
	result = c.checkEndpoints(context.Background(), time.Now(), 0, transport)
	transport.CloseIdleConnections()
	if !result.Healthy || !result.TransportOK || result.ServiceOK {
		t.Fatalf("HTTP application errors should indicate reachable VPN but unhealthy control services: %+v", result)
	}
}

func TestPassiveMassProxyFailuresNeedConfirmationAndRouteRecovers(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	socks := newTestSocks(t, strings.TrimPrefix(origin.URL, "https://"))
	socks.available.Store(false)
	p := &Profile{ID: "active", Name: "active", Priority: 0, Healthy: true, State: "HEALTHY", enabled: true, session: &testSession{addr: socks.Addr()}, restartReq: make(chan struct{}, 1)}
	s := Settings{}
	s.Failover.Enabled = true
	s.Failover.CheckTimeout = time.Second
	s.Failover.TLSHandshakeTimeout = time.Second
	s.Failover.FailureThreshold = 2
	s.Failover.RecoveryThreshold = 2
	s.Health.RequiredSuccesses = 1
	s.Health.URLs = []string{origin.URL}
	c := &Controller{profiles: []*Profile{p}, settings: s}
	c.active.Store(p)
	c.noteProxyFailure(p, &SOCKSError{Stage: "socks5_connect", Err: errors.New("connect timeout")})
	p.mu.Lock()
	stillHealthy := p.Healthy
	p.mu.Unlock()
	if c.active.Load() != p || !stillHealthy {
		t.Fatal("one passive CONNECT timeout bypassed the configured failure threshold")
	}
	c.noteProxyFailure(p, &SOCKSError{Stage: "socks5_connect", Err: errors.New("connect timeout")})
	firstConfirmationDone := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		p.mu.Lock()
		firstConfirmationDone = p.Failures >= 1 && !p.confirming
		p.mu.Unlock()
		if firstConfirmationDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !firstConfirmationDone {
		t.Fatal("first passive-triggered active confirmation did not complete")
	}
	c.noteProxyFailure(p, &SOCKSError{Stage: "socks5_connect", Err: errors.New("connect timeout")})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		unhealthy := p.State == "UNHEALTHY"
		p.mu.Unlock()
		if unhealthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.active.Load() != nil {
		t.Fatal("confirmed failure did not fail closed with no healthy route")
	}
	socks.available.Store(true)
	for i := 0; i < 2; i++ {
		c.recordHealth(p, healthResult{Healthy: true, TransportOK: true, ServiceOK: true})
	}
	if c.active.Load() != p {
		t.Fatal("profile did not safely recover after consecutive independent HTTPS probes")
	}
}

func portOf(hostport string) int {
	_, port, _ := net.SplitHostPort(hostport)
	n, _ := strconv.Atoi(port)
	return n
}

func TestProxyRejectsAllTrafficWithoutHealthyProfile(t *testing.T) {
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
	}{Enabled: true}}, requests: make(chan struct{}, 2)}
	proxy := httptest.NewServer(c.proxyHandler())
	defer proxy.Close()
	client := proxyClient(t, proxy.URL)
	resp, err := client.Get("http://destination.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("all-down response=%d", resp.StatusCode)
	}
}

func TestLargeRequestAndCanceledClientClose(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", fmt.Sprint(64<<20))
		for i := 0; i < 64; i++ {
			if _, e := w.Write(make([]byte, 1<<20)); e != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer origin.Close()
	socks := newTestSocks(t, strings.TrimPrefix(origin.URL, "http://"))
	c := testController(t, socks.Addr())
	proxy := httptest.NewServer(c.proxyHandler())
	defer proxy.Close()
	client := proxyClient(t, proxy.URL)
	requestBody := strings.NewReader(strings.Repeat("a", 4<<20))
	req, _ := http.NewRequest(http.MethodPost, origin.URL+"/upload", requestBody)
	cancelCtx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(cancelCtx)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = resp.Body.Close()
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	done := make(chan struct{})
	go func() { defer close(done); proxy.Close() }()
	select {
	case <-done:
	case <-closeCtx.Done():
		t.Fatal("proxy close stalled after client cancellation")
	}
}

func TestFailoverE2EChangesBackendAndFailsClosed(t *testing.T) {
	origin := func(ip string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusNoContent)
			case "/ip":
				_, _ = io.WriteString(w, ip)
			default:
				http.NotFound(w, r)
			}
		}))
	}
	p1, p2, p3 := origin("198.51.100.11"), origin("198.51.100.22"), origin("198.51.100.33")
	defer p1.Close()
	defer p2.Close()
	defer p3.Close()
	var directHits atomic.Int32
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directHits.Add(1)
		_, _ = io.WriteString(w, "DIRECT-LEAK")
	}))
	defer direct.Close()
	engine := &testEngine{t: t, routes: map[string]string{"primary": strings.TrimPrefix(p1.URL, "http://"), "backup1": strings.TrimPrefix(p2.URL, "http://"), "backup2": strings.TrimPrefix(p3.URL, "http://")}, sessions: make(map[string]*testSocks)}
	settings := Settings{}
	settings.Failover.Enabled = true
	settings.Failover.CheckInterval = 10 * time.Millisecond
	settings.Failover.CheckTimeout = 200 * time.Millisecond
	settings.Failover.FailureThreshold = 2
	settings.Failover.RecoveryThreshold = 2
	settings.Failover.RecoveryInterval = 10 * time.Millisecond
	settings.Failover.SwitchCooldown = 10 * time.Millisecond
	settings.Health.URLs = []string{"http://health.invalid/health"}
	settings.Health.RequiredSuccesses = 1
	profiles := []*Profile{
		{Name: "primary", ID: "primary", Priority: 0, State: "STARTING", config: []byte("primary"), restartReq: make(chan struct{}, 1)},
		{Name: "backup1", ID: "backup1", Priority: 1, State: "STARTING", config: []byte("backup1"), restartReq: make(chan struct{}, 1)},
		{Name: "backup2", ID: "backup2", Priority: 2, State: "STARTING", config: []byte("backup2"), restartReq: make(chan struct{}, 1)},
	}
	c := &Controller{profiles: profiles, settings: settings, started: time.Now(), engine: engine, runtimeDir: t.TempDir(), maxEngines: 3, requests: make(chan struct{}, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	c.start(ctx)
	defer func() {
		cancel()
		c.wg.Wait()
		for _, p := range profiles {
			if p.transport != nil {
				p.transport.CloseIdleConnections()
			}
		}
	}()
	proxy := httptest.NewServer(c.proxyHandler())
	defer proxy.Close()
	client := proxyClient(t, proxy.URL)
	waitActive := func(want string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if c.snapshot().Active == want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("active profile did not converge to %q; got %q status=%+v", want, c.snapshot().Active, c.snapshot().Profiles)
	}
	assertIP := func(want string) {
		t.Helper()
		resp, err := client.Get("http://whoami.invalid/ip")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("routed response=%d %q; want backend %q", resp.StatusCode, body, want)
		}
	}
	waitActive("primary")
	assertIP("198.51.100.11")
	engine.setAvailable("primary", false)
	waitActive("backup1")
	assertIP("198.51.100.22")
	engine.setAvailable("backup1", false)
	waitActive("backup2")
	assertIP("198.51.100.33")
	engine.setAvailable("primary", true)
	waitActive("primary")
	assertIP("198.51.100.11")
	engine.setAvailable("primary", false)
	engine.setAvailable("backup1", false)
	engine.setAvailable("backup2", false)
	deadline := time.Now().Add(3 * time.Second)
	for c.active.Load() != nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.active.Load() != nil {
		t.Fatal("expected nil active profile when all routes fail")
	}
	resp, err := client.Get("http://direct.invalid/secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("all-down proxy status=%d", resp.StatusCode)
	}
	if directHits.Load() != 0 {
		t.Fatalf("DIRECT target was reached %d times", directHits.Load())
	}
}

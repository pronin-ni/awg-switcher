package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"
)

const maxNetworkTraces = 100

type traceContextKey struct{}

type TraceStage struct {
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// NetworkTrace intentionally contains hostname and transport metadata only;
// URL paths, query strings, headers, body data and VPN configuration are never
// retained in diagnostic history or support exports.
type NetworkTrace struct {
	TraceID         string                `json:"trace_id"`
	StartedAt       time.Time             `json:"started_at"`
	ProfileID       string                `json:"profile_id,omitempty"`
	ProfileName     string                `json:"profile_name,omitempty"`
	EngineState     string                `json:"engine_state,omitempty"`
	Hostname        string                `json:"hostname,omitempty"`
	AddressType     string                `json:"address_type,omitempty"`
	DNS             string                `json:"dns"`
	Stages          map[string]TraceStage `json:"stages"`
	SOCKSReplyCode  *byte                 `json:"socks_reply_code,omitempty"`
	HTTPStatus      int                   `json:"http_status,omitempty"`
	FailureStage    string                `json:"failure_stage,omitempty"`
	ErrorType       string                `json:"error_type,omitempty"`
	Error           string                `json:"error,omitempty"`
	Deadline        string                `json:"deadline"`
	DeadlineAt      time.Time             `json:"deadline_at,omitempty"`
	TotalDurationMS int64                 `json:"total_duration_ms"`
	mu              *sync.Mutex           `json:"-"`
}

func (t *NetworkTrace) lock() func() {
	if t.mu == nil {
		t.mu = &sync.Mutex{}
	}
	t.mu.Lock()
	return t.mu.Unlock
}

func newNetworkTrace(p *Profile, target string) *NetworkTrace {
	token, _ := randomToken(12)
	t := &NetworkTrace{
		TraceID: token, StartedAt: time.Now().UTC(), DNS: "not_observable_inside_engine",
		Stages: map[string]TraceStage{}, Deadline: "manual_diagnostic_30s", mu: &sync.Mutex{},
	}
	if p != nil {
		p.mu.Lock()
		t.ProfileID, t.ProfileName, t.EngineState = p.ID, p.Name, p.State
		p.mu.Unlock()
	}
	t.Hostname = target
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		if ip.To4() != nil {
			t.AddressType = "IPv4"
		} else {
			t.AddressType = "IPv6"
		}
	} else if target != "" {
		t.AddressType = "DOMAIN"
	}
	return t
}

func withNetworkTrace(ctx context.Context, trace *NetworkTrace) context.Context {
	return context.WithValue(ctx, traceContextKey{}, trace)
}

func traceFromContext(ctx context.Context) *NetworkTrace {
	trace, _ := ctx.Value(traceContextKey{}).(*NetworkTrace)
	return trace
}

func (t *NetworkTrace) stage(name, status string, elapsed time.Duration, detail string) {
	if t == nil {
		return
	}
	unlock := t.lock()
	t.Stages[name] = TraceStage{Status: status, DurationMS: elapsed.Milliseconds(), Detail: detail}
	unlock()
}

func (t *NetworkTrace) fail(stage string, err error) {
	if t == nil || err == nil {
		return
	}
	unlock := t.lock()
	t.FailureStage = stage
	t.ErrorType = classifyHealthError(err)
	// Error text is limited to the concrete transport error; no request content
	// or URL path/query can enter this value.
	t.Error = safeTransportError(err)
	unlock()
}

func safeTransportError(err error) string {
	var socksErr *SOCKSError
	if errors.As(err, &socksErr) {
		if socksErr.ReplyCode != nil {
			return socksErr.Error()
		}
		return socksErr.Stage + ": " + classifyHealthError(socksErr.Err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "operation timed out"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "DNS operation timed out inside VPN engine"
		}
		return "DNS resolution failed inside VPN engine"
	}
	return classifyHealthError(err)
}

func (t *NetworkTrace) finish() {
	if t == nil {
		return
	}
	unlock := t.lock()
	t.TotalDurationMS = time.Since(t.StartedAt).Milliseconds()
	unlock()
}

func (t *NetworkTrace) setHTTPStatus(status int) {
	if t == nil {
		return
	}
	unlock := t.lock()
	t.HTTPStatus = status
	unlock()
}

func (t *NetworkTrace) setDeadline(source string, deadline time.Time) {
	if t == nil {
		return
	}
	unlock := t.lock()
	t.Deadline = source
	t.DeadlineAt = deadline.UTC()
	unlock()
}

func (t *NetworkTrace) snapshot() NetworkTrace {
	unlock := t.lock()
	defer unlock()
	copy := *t
	copy.mu = nil
	copy.Stages = make(map[string]TraceStage, len(t.Stages))
	for k, v := range t.Stages {
		copy.Stages[k] = v
	}
	return copy
}

func (c *Controller) recordNetworkTrace(t NetworkTrace) {
	c.networkDebugMu.Lock()
	c.networkTraces = append(c.networkTraces, t)
	if len(c.networkTraces) > maxNetworkTraces {
		c.networkTraces = append([]NetworkTrace(nil), c.networkTraces[len(c.networkTraces)-maxNetworkTraces:]...)
	}
	c.networkDebugMu.Unlock()
	if enabled, _ := c.networkDebugState(); enabled {
		slog.Info("network diagnostic trace", "trace_id", t.TraceID, "profile_id", t.ProfileID, "hostname", t.Hostname, "failure_stage", t.FailureStage, "error_type", t.ErrorType, "duration_ms", t.TotalDurationMS)
	}
}

func (c *Controller) networkDebugState() (bool, time.Time) {
	c.networkDebugMu.Lock()
	defer c.networkDebugMu.Unlock()
	if time.Now().After(c.networkDebugUntil) {
		c.networkDebugUntil = time.Time{}
	}
	return !c.networkDebugUntil.IsZero(), c.networkDebugUntil
}

func (c *Controller) setNetworkDebug(enabled bool) time.Time {
	c.networkDebugMu.Lock()
	defer c.networkDebugMu.Unlock()
	if enabled {
		c.networkDebugUntil = time.Now().Add(10 * time.Minute)
	} else {
		c.networkDebugUntil = time.Time{}
	}
	return c.networkDebugUntil
}

func (c *Controller) networkTraceSnapshot() []NetworkTrace {
	c.networkDebugMu.Lock()
	defer c.networkDebugMu.Unlock()
	result := make([]NetworkTrace, len(c.networkTraces))
	copy(result, c.networkTraces)
	return result
}

func appRuntimeVersion() string { return version + " (" + runtime.Version() + ")" }

func (c *Controller) supportBundle() map[string]any {
	debug, until := c.networkDebugState()
	snapshot := c.snapshot()
	profiles := make([]map[string]any, 0, len(snapshot.Profiles))
	for _, p := range snapshot.Profiles {
		profiles = append(profiles, map[string]any{
			"id": p.ID, "name": p.Name, "priority": p.Priority, "state": p.State,
			"healthy": p.Healthy, "last_check": p.LastCheck, "last_success": p.LastSuccess,
			"health_latency_ms": p.HealthLatencyMS, "external_ip": p.ExternalIP,
			"failures": p.Failures, "successes": p.Successes, "restarts": p.Restarts,
		})
	}
	events := make([]ControllerEvent, len(snapshot.Events))
	for i, event := range snapshot.Events {
		events[i] = event
		if event.Kind == "profile_error" {
			events[i].Message = "profile health check failed"
		}
	}
	status := map[string]any{
		"active": snapshot.Active, "profiles": profiles, "since": snapshot.Since,
		"switches": snapshot.Switches, "last_switch": snapshot.LastSwitch,
		"manual_until": snapshot.ManualUntil, "active_connections": snapshot.ActiveConnections,
		"events": events,
	}
	return map[string]any{
		"generated_at": time.Now().UTC(), "application_version": appRuntimeVersion(),
		"runtime": map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "engine_output": "suppressed_untrusted_not_exported"},
		"status":  status, "diagnostic_history": c.networkTraceSnapshot(),
		"network_debug": map[string]any{"enabled": debug, "expires_at": until},
	}
}

func (c *Controller) debugNetworkTrace(t NetworkTrace) {
	if enabled, _ := c.networkDebugState(); enabled {
		c.recordNetworkTrace(t)
	}
}

func proxyFailureStage(err error) string {
	var socksErr *SOCKSError
	if errors.As(err, &socksErr) {
		return socksErr.Stage
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && strings.Contains(strings.ToLower(urlErr.Err.Error()), "tls") {
		return "tls_handshake"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "transport_timeout_stage_unknown"
	}
	return "transport"
}

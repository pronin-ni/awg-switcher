package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newAutoTestServer(t *testing.T) *webServer {
	t.Helper()
	dir := t.TempDir()
	cfg := Settings{}
	cfg.Failover.CheckInterval = 5 * time.Second
	c := &Controller{settings: cfg, profiles: []*Profile{}}
	s := &webServer{controller: c, dataDir: dir, autoConfig: defaultAutoReplenishmentConfig()}
	return s
}

func TestAutoReplenishmentOffNeverCallsGenerator(t *testing.T) {
	s := newAutoTestServer(t)
	var calls atomic.Int32
	s.autoRunFunc = func(context.Context, configGeneratorSettings, string, int) (generatedConfigResponse, error) {
		calls.Add(1)
		return generatedConfigResponse{}, nil
	}
	if err := s.runAutoReplenishment(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("generator called %d times while automation disabled", calls.Load())
	}
}

func TestAutoReplenishmentNoShortageNeverCallsGenerator(t *testing.T) {
	s := newAutoTestServer(t)
	s.autoConfig = defaultAutoReplenishmentConfig()
	s.autoConfig.Enabled = true
	now := time.Now()
	for i := 0; i < 3; i++ {
		s.controller.profiles = append(s.controller.profiles, &Profile{ID: string(rune('a' + i)), State: "HEALTHY", Healthy: true, enabled: true, LastCheck: now, RoutingEligible: true})
	}
	var calls atomic.Int32
	s.autoRunFunc = func(context.Context, configGeneratorSettings, string, int) (generatedConfigResponse, error) {
		calls.Add(1)
		return generatedConfigResponse{}, nil
	}
	if err := s.runAutoReplenishment(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("generator called %d times with sufficient profiles", calls.Load())
	}
}

func TestAutoWebsiteMonitorSettingCanIgnoreWebsitePolicy(t *testing.T) {
	s := newAutoTestServer(t)
	p := &Profile{ID: "healthy", State: "HEALTHY", Healthy: true, enabled: true, LastCheck: time.Now(), RoutingEligible: true}
	s.controller.profiles = []*Profile{p}
	s.controller.websiteMu.Lock()
	s.controller.websiteConfig = WebsiteMonitorConfig{Enabled: true, Policy: "all_required", Websites: []Website{{ID: "required", Enabled: true, Required: true}}}
	s.controller.websiteMu.Unlock()
	cfg := defaultAutoReplenishmentConfig()
	cfg.UseWebsiteMonitor = false
	ready, _, _ := s.eligibleProfileCounts(cfg)
	if ready != 1 {
		t.Fatalf("website policy was applied while disabled in auto settings: ready=%d", ready)
	}
	cfg.UseWebsiteMonitor = true
	ready, _, _ = s.eligibleProfileCounts(cfg)
	if ready != 0 {
		t.Fatalf("profile without fresh website result was counted ready: %d", ready)
	}
}

func TestAutoReplenishmentPersistsConfigAndState(t *testing.T) {
	dir := t.TempDir()
	s := &webServer{dataDir: dir, autoConfig: defaultAutoReplenishmentConfig()}
	s.autoConfig.Enabled = true
	s.autoConfig.MinimumReady = 3
	s.autoConfig.TargetReady = 5
	if err := s.saveAutoReplenishment(s.autoConfig); err != nil {
		t.Fatal(err)
	}
	s.autoState.Attempts = []time.Time{time.Now().UTC()}
	s.autoState.CooldownUntil = time.Now().Add(time.Hour).UTC()
	s.autoState.Events = []AutoReplenishmentEvent{{At: time.Now().UTC(), Kind: "started", Message: "safe"}}
	if err := saveAutoReplenishmentState(dir, s.autoState); err != nil {
		t.Fatal(err)
	}
	loaded := &webServer{dataDir: dir}
	if err := loaded.loadAutoReplenishment(); err != nil {
		t.Fatal(err)
	}
	if !loaded.autoConfig.Enabled || loaded.autoConfig.MinimumReady != 3 || loaded.autoConfig.TargetReady != 5 {
		t.Fatalf("settings did not persist: %+v", loaded.autoConfig)
	}
	if len(loaded.autoState.Attempts) != 1 || loaded.autoState.CooldownUntil.IsZero() || len(loaded.autoState.Events) != 1 {
		t.Fatalf("state did not persist: %+v", loaded.autoState)
	}
	for _, name := range []string{"auto-replenishment.json", "auto-replenishment-state.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestAutoReplenishmentBoundsAndDeletionAreRejected(t *testing.T) {
	cfg := defaultAutoReplenishmentConfig()
	cfg.TargetReady = cfg.MinimumReady - 1
	if err := validateAutoReplenishmentConfig(cfg); err == nil {
		t.Fatal("accepted target below minimum")
	}
	cfg = defaultAutoReplenishmentConfig()
	cfg.AutoDeleteOldProfiles = true
	if err := validateAutoReplenishmentConfig(cfg); err == nil {
		t.Fatal("accepted unsupported automatic deletion")
	}
}

func TestAutoReplenishmentRateLimitBackoffAndDailyLimitPersist(t *testing.T) {
	s := newAutoTestServer(t)
	s.autoConfig = defaultAutoReplenishmentConfig()
	s.autoState.Attempts = []time.Time{time.Now().UTC()}
	retry := 3 * time.Hour
	s.finishAutoRun("unavailable", "Generator unavailable.", 0, 0, 0, true, retry)
	if time.Until(s.autoState.CooldownUntil) < retry-time.Second {
		t.Fatalf("Retry-After was not honored: until=%s", s.autoState.CooldownUntil)
	}
	loaded := AutoReplenishmentState{}
	b, err := os.ReadFile(autoReplenishmentStatePath(s.dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.Attempts) != 1 || loaded.CooldownUntil.IsZero() {
		t.Fatalf("attempt/cooldown did not persist: %+v", loaded)
	}
	s.autoState = loaded
	s.autoState.CooldownUntil = time.Time{}
	s.autoState.Attempts = make([]time.Time, s.autoConfig.MaxAttemptsPerDay)
	for i := range s.autoState.Attempts {
		s.autoState.Attempts[i] = time.Now().Add(-time.Duration(i) * time.Minute)
	}
	s.autoConfig.Enabled = true
	var calls atomic.Int32
	s.autoRunFunc = func(context.Context, configGeneratorSettings, string, int) (generatedConfigResponse, error) {
		calls.Add(1)
		return generatedConfigResponse{}, nil
	}
	if err := s.runAutoReplenishment(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("generator was called after reaching daily attempt limit")
	}
	if s.autoState.LastRunStatus != "limit" {
		t.Fatalf("daily limit status=%q", s.autoState.LastRunStatus)
	}
}

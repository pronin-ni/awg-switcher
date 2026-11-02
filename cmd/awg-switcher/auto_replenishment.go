package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	autoReplenishmentMaxEvents = 300
	maxAutoBackoff             = 24 * time.Hour
)

type AutoReplenishmentConfig struct {
	Enabled                bool     `json:"enabled"`
	MinimumReady           int      `json:"minimum_ready"`
	TargetReady            int      `json:"target_ready"`
	AutoActivate           bool     `json:"auto_activate"`
	GenerateBelowMinimum   bool     `json:"generate_below_minimum"`
	GenerateWhenAllDown    bool     `json:"generate_when_all_down"`
	CheckIntervalMinutes   int      `json:"check_interval_minutes"`
	FailureCooldownMinutes int      `json:"failure_cooldown_minutes"`
	MaxPerRun              int      `json:"max_per_run"`
	MaxAttemptsPerDay      int      `json:"max_attempts_per_day"`
	MaxSavedProfiles       int      `json:"max_saved_profiles"`
	AutoDeleteOldProfiles  bool     `json:"auto_delete_old_profiles"`
	UseWebsiteMonitor      bool     `json:"use_website_monitor"`
	NotifyLowPool          bool     `json:"notify_low_pool"`
	AutoDeleteFailed       bool     `json:"auto_delete_failed_profiles"`
	Versions               []string `json:"versions"`
}

type AutoReplenishmentEvent struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	Created int       `json:"created,omitempty"`
	Passed  int       `json:"passed,omitempty"`
	Added   int       `json:"added,omitempty"`
}

type AutoReplenishmentState struct {
	Attempts            []time.Time              `json:"attempts,omitempty"`
	CooldownUntil       time.Time                `json:"cooldown_until,omitempty"`
	ConsecutiveFailures int                      `json:"consecutive_failures,omitempty"`
	LastRun             time.Time                `json:"last_run,omitempty"`
	LastRunStatus       string                   `json:"last_run_status,omitempty"`
	LastRunError        string                   `json:"last_run_error,omitempty"`
	LastCreated         int                      `json:"last_created,omitempty"`
	LastPassed          int                      `json:"last_passed,omitempty"`
	LastAdded           int                      `json:"last_added,omitempty"`
	Events              []AutoReplenishmentEvent `json:"events,omitempty"`
}

type autoCandidateResult struct {
	Created bool
	Passed  bool
	Added   bool
	Error   string
}

func defaultAutoReplenishmentConfig() AutoReplenishmentConfig {
	return AutoReplenishmentConfig{
		Enabled: false, MinimumReady: 2, TargetReady: 4, AutoActivate: true,
		GenerateBelowMinimum: true, GenerateWhenAllDown: true,
		CheckIntervalMinutes: 30, FailureCooldownMinutes: 60,
		MaxPerRun: 3, MaxAttemptsPerDay: 6, MaxSavedProfiles: 20,
		AutoDeleteOldProfiles: false, UseWebsiteMonitor: true,
		NotifyLowPool: true, AutoDeleteFailed: false,
		Versions: []string{"awg2", "awg3", "awg31"},
	}
}

func validateAutoReplenishmentConfig(c AutoReplenishmentConfig) error {
	if c.MinimumReady < 1 || c.MinimumReady > 10 {
		return errors.New("minimum_ready must be between 1 and 10")
	}
	if c.TargetReady < c.MinimumReady || c.TargetReady > 20 {
		return errors.New("target_ready must be at least the minimum and no more than 20")
	}
	if c.CheckIntervalMinutes < 5 || c.CheckIntervalMinutes > 1440 {
		return errors.New("check interval must be between 5 and 1440 minutes")
	}
	if c.FailureCooldownMinutes < 15 || c.FailureCooldownMinutes > 1440 {
		return errors.New("failure cooldown must be between 15 and 1440 minutes")
	}
	if c.MaxPerRun < 1 || c.MaxPerRun > 3 {
		return errors.New("maximum new profiles per run must be between 1 and 3")
	}
	if c.MaxAttemptsPerDay < 1 || c.MaxAttemptsPerDay > 6 {
		return errors.New("maximum generation attempts per day must be between 1 and 6")
	}
	if c.MaxSavedProfiles < 1 || c.MaxSavedProfiles > 20 {
		return errors.New("maximum saved profiles must be between 1 and 20")
	}
	if c.AutoDeleteOldProfiles || c.AutoDeleteFailed {
		return errors.New("automatic profile deletion is not implemented; leave it disabled")
	}
	if len(c.Versions) == 0 || len(c.Versions) > 3 {
		return errors.New("select at least one AWG version")
	}
	seen := map[string]bool{}
	for _, v := range c.Versions {
		if v != "awg2" && v != "awg3" && v != "awg31" {
			return errors.New("unsupported AWG version")
		}
		if seen[v] {
			return errors.New("duplicate AWG version")
		}
		seen[v] = true
	}
	return nil
}

func autoReplenishmentConfigPath(dir string) string {
	return filepath.Join(dir, "auto-replenishment.json")
}
func autoReplenishmentStatePath(dir string) string {
	return filepath.Join(dir, "auto-replenishment-state.json")
}

func (s *webServer) loadAutoReplenishment() error {
	cfg := defaultAutoReplenishmentConfig()
	path := autoReplenishmentConfigPath(s.dataDir)
	b, err := readSecureJSON(path, 128<<10)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err = json.Unmarshal(b, &cfg); err != nil {
			return errors.New("automatic replenishment settings are invalid")
		}
		if err = validateAutoReplenishmentConfig(cfg); err != nil {
			return err
		}
	}
	state := AutoReplenishmentState{}
	b, err = readSecureJSON(autoReplenishmentStatePath(s.dataDir), 4<<20)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err = json.Unmarshal(b, &state); err != nil {
			return errors.New("automatic replenishment state is invalid")
		}
	}
	state.Attempts = pruneAutoAttempts(state.Attempts, time.Now())
	if state.LastRunStatus == "running" {
		now := time.Now()
		state.LastRunStatus = "interrupted"
		state.LastRunError = "Generation was interrupted by application restart; the attempt remains counted."
		state.ConsecutiveFailures++
		backoff := time.Duration(1<<min(state.ConsecutiveFailures-1, 10)) * time.Duration(cfg.FailureCooldownMinutes) * time.Minute
		if backoff > maxAutoBackoff {
			backoff = maxAutoBackoff
		}
		candidate := now.Add(backoff)
		if candidate.After(state.CooldownUntil) {
			state.CooldownUntil = candidate
		}
		state.Events = append(state.Events, AutoReplenishmentEvent{At: now.UTC(), Kind: "interrupted", Message: "An in-flight generation was interrupted by restart; its daily attempt remains counted."})
	}
	if len(state.Events) > autoReplenishmentMaxEvents {
		state.Events = append([]AutoReplenishmentEvent(nil), state.Events[len(state.Events)-autoReplenishmentMaxEvents:]...)
	}
	if err := saveAutoReplenishmentState(s.dataDir, state); err != nil {
		return err
	}
	s.autoMu.Lock()
	s.autoConfig = cfg
	s.autoState = state
	s.autoNextCheck = time.Now().Add(time.Duration(cfg.CheckIntervalMinutes) * time.Minute)
	s.autoMu.Unlock()
	return nil
}

func readSecureJSON(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, errors.New("automatic replenishment storage permissions or size are unsafe")
	}
	return os.ReadFile(path)
}

func (s *webServer) saveAutoReplenishment(cfg AutoReplenishmentConfig) error {
	if err := validateAutoReplenishmentConfig(cfg); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicPrivateWrite(s.dataDir, autoReplenishmentConfigPath(s.dataDir), b)
}
func saveAutoReplenishmentState(dir string, state AutoReplenishmentState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicPrivateWrite(dir, autoReplenishmentStatePath(dir), b)
}

func (s *webServer) persistAutoReplenishmentState() error {
	// Serialize snapshot+rename, not just the write: concurrent event writers
	// must never persist an older state after a newer state.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.autoMu.RLock()
	state := s.autoState
	state.Attempts = append([]time.Time(nil), s.autoState.Attempts...)
	state.Events = append([]AutoReplenishmentEvent(nil), s.autoState.Events...)
	s.autoMu.RUnlock()
	return saveAutoReplenishmentState(s.dataDir, state)
}
func atomicPrivateWrite(dir, path string, b []byte) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".auto-replenishment-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func pruneAutoAttempts(in []time.Time, now time.Time) []time.Time {
	out := make([]time.Time, 0, len(in))
	cutoff := now.Add(-24 * time.Hour)
	for _, at := range in {
		if at.After(cutoff) && !at.After(now.Add(time.Minute)) {
			out = append(out, at)
		}
	}
	return out
}

func (s *webServer) autoConfigSnapshot() AutoReplenishmentConfig {
	s.autoMu.RLock()
	defer s.autoMu.RUnlock()
	cfg := s.autoConfig
	cfg.Versions = append([]string(nil), cfg.Versions...)
	return cfg
}

func (s *webServer) appendAutoEvent(kind, message string, created, passed, added int) {
	s.autoMu.Lock()
	s.autoState.Events = append(s.autoState.Events, AutoReplenishmentEvent{At: time.Now().UTC(), Kind: kind, Message: message, Created: created, Passed: passed, Added: added})
	if len(s.autoState.Events) > autoReplenishmentMaxEvents {
		s.autoState.Events = append([]AutoReplenishmentEvent(nil), s.autoState.Events[len(s.autoState.Events)-autoReplenishmentMaxEvents:]...)
	}
	s.autoMu.Unlock()
	if err := s.persistAutoReplenishmentState(); err != nil {
		slogWarnAuto("state persistence failed")
	}
}

func slogWarnAuto(message string) { /* avoid logging generated credentials or upstream response bodies */
	_ = message
}

func (s *webServer) eligibleProfileCounts(cfg AutoReplenishmentConfig) (ready, reserved, total int) {
	monitor := s.controller.websiteConfigSnapshot()
	policy := websitePolicyApplies(monitor)
	interval := s.controller.settings.Failover.CheckInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	freshness := 2 * interval
	if freshness < time.Minute {
		freshness = time.Minute
	}
	for _, p := range s.controller.profilesSnapshot() {
		p.mu.Lock()
		total++
		enabled, healthy, state, last := p.enabled, p.Healthy, p.State, p.LastCheck
		eligible := enabled && healthy && state == "HEALTHY" && !last.IsZero() && time.Since(last) <= freshness
		if eligible && policy && cfg.UseWebsiteMonitor {
			if p.WebsiteState != "PASSED" || !p.RoutingEligible || p.WebsiteLastCheck.IsZero() || time.Since(p.WebsiteLastCheck) > freshness {
				eligible = false
			}
		}
		if eligible {
			ready++
		} else if p.AutoGenerated && p.AutoCandidate && (p.AutoVerifyReason == "verification pending" || (p.AutoVerified && !enabled) || (enabled && healthy == false && state != "UNHEALTHY" && state != "DISABLED")) {
			reserved++
		}
		p.mu.Unlock()
	}
	return
}

func (s *webServer) autoStatus() map[string]any {
	cfg := s.autoConfigSnapshot()
	ready, reserved, total := s.eligibleProfileCounts(cfg)
	s.autoMu.RLock()
	state := s.autoState
	next, running := s.autoNextCheck, s.autoTaskRunning
	s.autoMu.RUnlock()
	state.Attempts = pruneAutoAttempts(state.Attempts, time.Now())
	remaining := cfg.MaxAttemptsPerDay - len(state.Attempts)
	if remaining < 0 {
		remaining = 0
	}
	return map[string]any{"settings": cfg, "enabled": cfg.Enabled, "running": running, "ready_profiles": ready, "reserved_candidates": reserved, "saved_profiles": total, "minimum_ready": cfg.MinimumReady, "target_ready": cfg.TargetReady, "next_check": next, "attempts_today": len(state.Attempts), "attempts_remaining": remaining, "cooldown_until": state.CooldownUntil, "last_run": state.LastRun, "last_run_status": state.LastRunStatus, "last_error": state.LastRunError, "last_created": state.LastCreated, "last_passed": state.LastPassed, "last_added": state.LastAdded, "events": state.Events, "website_global_failure": s.controller.websiteStatusResponse()["global_site_failures"]}
}

func (s *webServer) startAutoReplenishment(ctx context.Context) {
	s.autoMu.Lock()
	if s.autoRunning {
		s.autoMu.Unlock()
		return
	}
	s.autoRunning = true
	if s.autoWake == nil {
		s.autoWake = make(chan struct{}, 1)
	}
	s.autoMu.Unlock()
	s.controller.wg.Add(1)
	go func() {
		defer s.controller.wg.Done()
		cfg := s.autoConfigSnapshot()
		if cfg.Enabled {
			initialDelay := s.controller.settings.Failover.CheckInterval
			if initialDelay <= 0 {
				initialDelay = 15 * time.Second
			}
			timer := time.NewTimer(initialDelay + 250*time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-s.autoWake:
				timer.Stop()
			case <-timer.C:
			}
			if s.autoConfigSnapshot().Enabled {
				_ = s.runAutoReplenishment(ctx)
			}
		}
		for {
			cfg = s.autoConfigSnapshot()
			wait := time.Duration(cfg.CheckIntervalMinutes) * time.Minute
			if wait < time.Minute {
				wait = 30 * time.Minute
			}
			s.autoMu.Lock()
			s.autoNextCheck = time.Now().Add(wait)
			s.autoMu.Unlock()
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-s.autoWake:
				timer.Stop()
				if s.autoConfigSnapshot().Enabled {
					_ = s.runAutoReplenishment(ctx)
				}
			case <-timer.C:
				if s.autoConfigSnapshot().Enabled {
					_ = s.runAutoReplenishment(ctx)
				}
			}
		}
	}()
}

func (s *webServer) wakeAutoReplenishment() {
	select {
	case s.autoWake <- struct{}{}:
	default:
	}
}

func (s *webServer) runAutoReplenishment(ctx context.Context) error {
	cfg := s.autoConfigSnapshot()
	if !cfg.Enabled {
		return nil
	}
	if !s.autoRunMu.TryLock() {
		return errors.New("automatic replenishment is already running")
	}
	defer s.autoRunMu.Unlock()
	return s.runAutoReplenishmentLocked(ctx, cfg)
}

func (s *webServer) runAutoReplenishmentLocked(ctx context.Context, cfg AutoReplenishmentConfig) error {
	if !s.autoConfigSnapshot().Enabled {
		return nil
	}
	s.autoMu.Lock()
	s.autoTaskRunning = true
	runCtx, cancelRun := context.WithCancel(ctx)
	s.autoCancel = cancelRun
	s.autoMu.Unlock()
	defer func() { cancelRun(); s.autoMu.Lock(); s.autoTaskRunning = false; s.autoCancel = nil; s.autoMu.Unlock() }()
	if !s.configGenRun.TryLock() {
		s.appendAutoEvent("deferred", "Another manual or automatic generator run is active.", 0, 0, 0)
		return errors.New("generator is busy")
	}
	defer s.configGenRun.Unlock()
	if err := s.recoverAutoCandidates(runCtx, cfg); err != nil {
		if runCtx.Err() != nil || !s.autoConfigSnapshot().Enabled {
			s.finishAutoRun("cancelled", "Automatic replenishment was disabled during candidate recovery.", 0, 0, 0, false, 0)
			return nil
		}
		s.finishAutoRun("error", "A persisted candidate could not be re-verified.", 0, 0, 0, true, 0)
		return err
	}
	ready, reserved, total := s.eligibleProfileCounts(cfg)
	if ready >= cfg.MinimumReady {
		return nil
	}
	s.appendAutoEvent("shortage", fmt.Sprintf("Only %d of %d minimum routing-eligible profiles are ready.", ready, cfg.MinimumReady), 0, 0, 0)
	if ready == 0 {
		if !cfg.GenerateWhenAllDown {
			s.finishAutoRun("deferred", "All profiles are unavailable; automatic generation on total outage is disabled.", 0, 0, 0, false, 0)
			return nil
		}
	} else if !cfg.GenerateBelowMinimum {
		s.finishAutoRun("deferred", "Automatic generation below the configured minimum is disabled.", 0, 0, 0, false, 0)
		return nil
	}
	if reserved > 0 {
		s.appendAutoEvent("deferred", fmt.Sprintf("%d generated candidate(s) are already awaiting activation or health checks.", reserved), 0, 0, 0)
		return nil
	}
	if total >= cfg.MaxSavedProfiles {
		s.finishAutoRun("limit", "Saved profile limit reached; no profiles were deleted.", 0, 0, 0, false, 0)
		return nil
	}
	s.autoMu.Lock()
	now := time.Now()
	s.autoState.Attempts = pruneAutoAttempts(s.autoState.Attempts, now)
	if now.Before(s.autoState.CooldownUntil) {
		until := s.autoState.CooldownUntil
		s.autoMu.Unlock()
		s.appendAutoEvent("cooldown", fmt.Sprintf("Generation deferred until %s.", until.UTC().Format(time.RFC3339)), 0, 0, 0)
		return nil
	}
	if len(s.autoState.Attempts) >= cfg.MaxAttemptsPerDay {
		s.autoMu.Unlock()
		s.finishAutoRun("limit", "Daily automatic generation attempt limit reached.", 0, 0, 0, false, 0)
		return nil
	}
	s.autoState.Attempts = append(s.autoState.Attempts, now)
	s.autoState.LastRun = now.UTC()
	s.autoState.LastRunStatus = "running"
	s.autoState.LastRunError = ""
	s.autoMu.Unlock()
	_ = s.persistAutoReplenishmentState()
	s.appendAutoEvent("started", fmt.Sprintf("Automatic generation started; ready=%d, target=%d.", ready, cfg.TargetReady), 0, 0, 0)
	settings, err := s.generatorSettings()
	if err != nil {
		s.finishAutoRun("unavailable", "Generator settings are unavailable.", 0, 0, 0, true, 0)
		return err
	}
	if len(cfg.Versions) == 0 {
		s.finishAutoRun("error", "No AWG versions are selected.", 0, 0, 0, true, 0)
		return errors.New("no AWG versions selected")
	}
	s.autoMu.RLock()
	attemptIndex := len(s.autoState.Attempts) - 1
	s.autoMu.RUnlock()
	mode := cfg.Versions[attemptIndex%len(cfg.Versions)]
	need := cfg.TargetReady - ready - reserved
	byRun := cfg.MaxPerRun
	if need < byRun {
		byRun = need
	}
	room := cfg.MaxSavedProfiles - total
	if byRun > room {
		byRun = room
	}
	if byRun < 1 {
		s.finishAutoRun("limit", "No capacity remains for new profile candidates.", 0, 0, 0, false, 0)
		return nil
	}
	deadline, cancel := context.WithTimeout(runCtx, generatorWorkflowTimeout)
	defer cancel()
	request := s.autoRunFunc
	if request == nil {
		request = requestWarpConfigs
	}
	result, err := request(deadline, settings, mode, byRun)
	if err != nil {
		retry := time.Duration(0)
		var apiErr *configGeneratorAPIError
		if errors.As(err, &apiErr) {
			retry = apiErr.RetryAfter
		}
		s.finishAutoRun("unavailable", "The configuration generator did not return usable profiles.", 0, 0, 0, true, retry)
		return err
	}
	// Settings can be switched off while a slow generator request is in flight.
	// Do not persist/launch any returned profiles after that opt-out.
	if runCtx.Err() != nil || !s.autoConfigSnapshot().Enabled {
		s.finishAutoRun("cancelled", "Automatic replenishment was disabled before candidates were accepted.", 0, 0, 0, false, 0)
		return nil
	}
	created, passed, added := 0, 0, 0
	seen := s.profileConfigHashes()
	for i, item := range result.Configs {
		if err := deadline.Err(); err != nil || runCtx.Err() != nil || !s.autoConfigSnapshot().Enabled {
			break
		}
		if created >= byRun {
			break
		}
		_, normalized, decodeErr := decodeGeneratedConfig(item.Content)
		if decodeErr != nil {
			s.appendAutoEvent("candidate_failed", "Generator returned a configuration that failed validation.", 0, 0, 0)
			continue
		}
		hash := sha256.Sum256(normalized)
		if seen[hash] {
			s.appendAutoEvent("duplicate", "Duplicate generated configuration was discarded.", 0, 0, 0)
			continue
		}
		seen[hash] = true
		id, path, storeErr := storeImportedProfile(s.dataDir, normalized)
		if storeErr != nil {
			s.appendAutoEvent("candidate_failed", "Could not securely store generated profile.", 0, 0, 0)
			continue
		}
		name := fmt.Sprintf("Auto WARP %s %d", map[string]string{"awg2": "AWG 2.0", "awg3": "AWG 3.0", "awg31": "AWG 3.1"}[mode], i+1)
		p, addErr := s.controller.addDisabledRuntimeProfile(id, name, normalized, path)
		if addErr != nil {
			_ = os.Remove(path)
			if strings.Contains(addErr.Error(), "already exists") {
				s.appendAutoEvent("duplicate", "Generated profile already exists and was skipped.", 0, 0, 0)
			} else {
				s.appendAutoEvent("candidate_failed", "Could not add generated candidate.", 0, 0, 0)
			}
			continue
		}
		p.mu.Lock()
		p.AutoGenerated = true
		p.AutoCandidate = true
		p.AutoVerified = false
		p.AutoVerifyReason = "verification pending"
		p.mu.Unlock()
		if err := s.persistState(); err != nil {
			s.appendAutoEvent("persistence_error", "New candidate state could not be persisted immediately.", 0, 0, 0)
		}
		created++
		s.appendAutoEvent("candidate_created", "Generated candidate saved disabled; temporary connectivity verification started.", 1, 0, 0)
		probeCtx, probeCancel := context.WithTimeout(deadline, 30*time.Second)
		verifyErr := s.verifyAutoCandidate(probeCtx, p, cfg)
		probeCancel()
		if verifyErr != nil {
			p.mu.Lock()
			p.AutoVerified = false
			p.AutoVerifyReason = safeAutoError(verifyErr.Error())
			p.LastError = "Generated profile verification failed: " + p.AutoVerifyReason
			p.mu.Unlock()
		}
		if verifyErr != nil {
			s.appendAutoEvent("candidate_failed", "Generated candidate failed real HTTPS verification: "+safeAutoError(verifyErr.Error()), 1, 0, 0)
			_ = s.persistState()
			continue
		}
		passed++
		s.appendAutoEvent("candidate_passed", "Generated candidate passed real HTTPS verification.", 1, 1, 0)
		if cfg.AutoActivate {
			if runCtx.Err() != nil || !s.autoConfigSnapshot().Enabled {
				s.appendAutoEvent("activation_skipped", "Verified candidate remains disabled because automatic replenishment was turned off.", 0, 1, 0)
				_ = s.persistState()
				continue
			}
			if !s.activateAutoCandidate(p) {
				s.appendAutoEvent("candidate_failed", "Verified profile could not be enabled.", 1, 1, 0)
				continue
			}
			added++
			s.appendAutoEvent("candidate_activated", "Verified profile added after existing profiles without changing their priorities.", 1, 1, 1)
		}
		if err := s.persistState(); err != nil {
			s.appendAutoEvent("persistence_error", "Profile status could not be persisted.", 0, 0, 0)
		}
	}
	if result.Warning != nil {
		s.appendAutoEvent("generator_warning", "Generator returned a warning; generated secrets were not recorded.", 0, 0, 0)
	}
	if passed == 0 {
		s.finishAutoRun("error", "No generated candidate passed verification.", created, passed, added, true, 0)
	} else {
		s.finishAutoRun("success", "Automatic generation run finished.", created, passed, added, false, 0)
	}
	return nil
}

func enabledWebsiteList(cfg WebsiteMonitorConfig) []Website {
	out := []Website{}
	for _, w := range cfg.Websites {
		if w.Enabled {
			out = append(out, w)
		}
	}
	return out
}

func (s *webServer) verifyAutoCandidate(ctx context.Context, p *Profile, cfg AutoReplenishmentConfig) error {
	websiteConfig := s.controller.websiteConfigSnapshot()
	policyHash := websitePolicyHash(websiteConfig)
	p.mu.Lock()
	configHash := sha256.Sum256(p.config)
	p.mu.Unlock()
	var results []WebsiteCheckResult
	var err error
	if s.autoVerifyFunc != nil {
		results, err = s.autoVerifyFunc(ctx, p, cfg.UseWebsiteMonitor)
	} else {
		_, results, err = s.controller.testGeneratedProfileDetailed(ctx, p, cfg.UseWebsiteMonitor)
	}
	if err == nil && cfg.UseWebsiteMonitor {
		webCfg := s.controller.websiteConfigSnapshot()
		if websitePolicyApplies(webCfg) {
			ok, _, reason, _ := websiteProfileEligible(webCfg, results, enabledWebsiteList(webCfg))
			if !ok {
				err = errors.New("website availability policy: " + reason)
			}
		}
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if policyHash != websitePolicyHash(s.controller.websiteConfigSnapshot()) {
		return errors.New("website policy changed during candidate verification; retry required")
	}
	p.mu.Lock()
	if sha256.Sum256(p.config) != configHash {
		p.mu.Unlock()
		return errors.New("candidate configuration changed during verification; retry required")
	}
	p.AutoVerified = true
	p.AutoVerifyReason = ""
	p.WebsiteLastCheck = time.Now().UTC()
	if websitePolicyApplies(websiteConfig) && cfg.UseWebsiteMonitor {
		p.WebsiteState = "PASSED"
		p.RoutingEligible = true
	}
	p.mu.Unlock()
	return nil
}

func (s *webServer) activateAutoCandidate(p *Profile) bool {
	s.controller.dynamicMu.Lock()
	defer s.controller.dynamicMu.Unlock()
	if s.controller.findProfile(p.ID) != p {
		return false
	}
	p.mu.Lock()
	if !p.AutoGenerated || !p.AutoCandidate || !p.AutoVerified {
		p.mu.Unlock()
		return false
	}
	if websitePolicyApplies(s.controller.websiteConfigSnapshot()) && (!p.RoutingEligible || p.WebsiteState != "PASSED") {
		p.mu.Unlock()
		return false
	}
	shouldLaunch := !p.enabled
	if shouldLaunch {
		p.enabled = true
		p.State = "CONNECTING"
		p.LastError = ""
	}
	enabled := p.enabled
	p.mu.Unlock()
	if shouldLaunch {
		s.controller.launchProfile(p)
	}
	return enabled
}

func (s *webServer) recoverAutoCandidates(ctx context.Context, cfg AutoReplenishmentConfig) error {
	for _, p := range s.controller.profilesSnapshot() {
		p.mu.Lock()
		pending := p.AutoGenerated && p.AutoCandidate && !p.AutoVerified && p.AutoVerifyReason == "verification pending"
		p.mu.Unlock()
		if !pending {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.verifyAutoCandidate(probeCtx, p, cfg)
		cancel()
		if err != nil {
			p.mu.Lock()
			p.AutoVerifyReason = safeAutoError(err.Error())
			p.LastError = "Generated profile verification failed: " + p.AutoVerifyReason
			p.mu.Unlock()
			s.appendAutoEvent("candidate_failed", "Recovered candidate failed verification: "+safeAutoError(err.Error()), 0, 0, 0)
			_ = s.persistState()
			return err
		}
		s.appendAutoEvent("candidate_passed", "Recovered candidate passed real HTTPS verification.", 0, 1, 0)
		if cfg.AutoActivate {
			if ctx.Err() != nil || !s.autoConfigSnapshot().Enabled {
				s.appendAutoEvent("activation_skipped", "Recovered candidate remains disabled because automatic replenishment was turned off.", 0, 1, 0)
				if err := s.persistState(); err != nil {
					return err
				}
				continue
			}
			if s.activateAutoCandidate(p) {
				s.appendAutoEvent("candidate_activated", "Recovered verified candidate added to the reserve pool.", 0, 1, 1)
			} else {
				s.appendAutoEvent("candidate_failed", "Recovered verified candidate could not be enabled.", 0, 1, 0)
			}
		}
		if err := s.persistState(); err != nil {
			return err
		}
	}
	return nil
}
func safeAutoError(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > 180 {
		raw = raw[:180]
	}
	return raw
}

func (s *webServer) profileConfigHashes() map[[32]byte]bool {
	out := map[[32]byte]bool{}
	for _, p := range s.controller.profilesSnapshot() {
		p.mu.Lock()
		config := append([]byte(nil), p.config...)
		p.mu.Unlock()
		if len(config) > 0 {
			out[sha256.Sum256(config)] = true
		}
	}
	return out
}

func (s *webServer) finishAutoRun(status, message string, created, passed, added int, failed bool, retryAfter time.Duration) {
	s.autoMu.Lock()
	now := time.Now()
	s.autoState.LastRun = now.UTC()
	s.autoState.LastRunStatus = status
	s.autoState.LastRunError = ""
	if failed {
		s.autoState.LastRunError = message
		s.autoState.ConsecutiveFailures++
		backoff := time.Duration(1<<min(s.autoState.ConsecutiveFailures-1, 10)) * time.Duration(s.autoConfig.FailureCooldownMinutes) * time.Minute
		if backoff > maxAutoBackoff {
			backoff = maxAutoBackoff
		}
		if retryAfter > backoff {
			backoff = retryAfter
		}
		if backoff > maxAutoBackoff {
			backoff = maxAutoBackoff
		}
		s.autoState.CooldownUntil = now.Add(backoff)
	} else if status == "success" {
		s.autoState.ConsecutiveFailures = 0
		s.autoState.CooldownUntil = time.Time{}
	}
	s.autoState.LastCreated = created
	s.autoState.LastPassed = passed
	s.autoState.LastAdded = added
	s.autoMu.Unlock()
	_ = s.persistAutoReplenishmentState()
	s.appendAutoEvent(status, message, created, passed, added)
}

func (s *webServer) automationAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auto-replenishment"), "/")
	switch path {
	case "settings":
		if r.Method == http.MethodGet {
			writeJSON(w, s.autoConfigSnapshot())
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		var cfg AutoReplenishmentConfig
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&cfg) != nil {
			http.Error(w, "invalid settings", 400)
			return
		}
		if err := validateAutoReplenishmentConfig(cfg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := s.saveAutoReplenishment(cfg); err != nil {
			http.Error(w, "could not save automatic replenishment settings", 500)
			return
		}
		s.autoMu.Lock()
		s.autoConfig = cfg
		s.autoNextCheck = time.Now().Add(time.Duration(cfg.CheckIntervalMinutes) * time.Minute)
		cancelTask := s.autoCancel
		s.autoMu.Unlock()
		s.appendAutoEvent("settings_saved", "Automatic replenishment settings were updated.", 0, 0, 0)
		if !cfg.Enabled && cancelTask != nil {
			cancelTask()
		}
		s.wakeAutoReplenishment()
		writeJSON(w, map[string]any{"saved": true, "status": s.autoStatus()})
	case "status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, s.autoStatus())
	case "check":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		cfg := s.autoConfigSnapshot()
		if !cfg.Enabled {
			http.Error(w, "automatic replenishment is disabled", http.StatusConflict)
			return
		}
		if !s.autoRunMu.TryLock() {
			http.Error(w, "automatic replenishment is already running", http.StatusConflict)
			return
		}
		go func() {
			defer s.autoRunMu.Unlock()
			ctx := s.controller.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			_ = s.runAutoReplenishmentLocked(ctx, cfg)
		}()
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"started": true, "status": s.autoStatus()})
	case "events":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		s.autoMu.RLock()
		events := append([]AutoReplenishmentEvent(nil), s.autoState.Events...)
		s.autoMu.RUnlock()
		writeJSON(w, events)
	default:
		http.NotFound(w, r)
	}
}

func (c *Controller) testGeneratedProfileDetailed(ctx context.Context, source *Profile, checkSites bool) (map[string]any, []WebsiteCheckResult, error) {
	if c.engine == nil {
		return nil, nil, errors.New("engine_unavailable")
	}
	temp := &Profile{ID: source.ID + "-probe", Name: "temporary WARP verification", State: "CONNECTING", config: append([]byte(nil), source.config...), enabled: true}
	c.prepareProfile(temp)
	session, err := c.engine.Start(ctx, temp.config, temp.socks, temp.slot)
	if err != nil {
		return map[string]any{"error_type": "engine_start_failed"}, nil, errors.New("engine_start_failed")
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
			return map[string]any{"error_type": "timeout"}, nil, errors.New("timeout")
		}
		select {
		case <-session.Done():
			return map[string]any{"error_type": "engine_exited"}, nil, errors.New("engine_exited")
		default:
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err = c.socksHandshake(handshakeCtx, session.SOCKSAddr())
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return map[string]any{"error_type": "socks_listener_unavailable"}, nil, errors.New("socks_listener_unavailable")
		}
		select {
		case <-ctx.Done():
			return map[string]any{"error_type": "timeout"}, nil, errors.New("timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
	checkURL := c.generatedIPCheckURL
	if checkURL == "" {
		checkURL = "https://api.ipify.org"
	}
	result := c.checkURL(ctx, temp, checkURL)
	status, _ := result["http_status"].(int)
	stages, _ := result["stages"].(map[string]TraceStage)
	socksStage, socksOK := stages["socks5_connect"]
	tlsStage, tlsOK := stages["tls_handshake"]
	failure, _ := result["failure_stage"].(string)
	if failure != "" || !socksOK || socksStage.Status != "success" || !tlsOK || tlsStage.Status != "success" || status < 200 || status >= 300 {
		reason, _ := result["error_type"].(string)
		if reason == "" {
			reason = "https_probe_failed"
		}
		return result, nil, errors.New(reason)
	}
	if !checkSites {
		return result, nil, nil
	}
	cfg := c.websiteConfigSnapshot()
	if !websitePolicyApplies(cfg) {
		return result, nil, nil
	}
	rows := []WebsiteCheckResult{}
	for _, site := range enabledWebsiteList(cfg) {
		timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		res := c.probeWebsite(probeCtx, temp, site, timeout)
		cancel()
		rows = append(rows, res.result)
	}
	if ok, _, reason, _ := websiteProfileEligible(cfg, rows, enabledWebsiteList(cfg)); !ok {
		return result, rows, errors.New("website availability policy: " + safeAutoError(reason))
	}
	return result, rows, nil
}

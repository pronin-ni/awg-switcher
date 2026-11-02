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
	"sort"
	"strings"
	"sync"
	"time"
)

type pendingWebsitePreview struct {
	Hash     [32]byte
	BaseHash [32]byte
	Expires  time.Time
}

func websiteConfigHash(cfg WebsiteMonitorConfig) [32]byte {
	b, _ := json.Marshal(cfg)
	return sha256.Sum256(b)
}
func websitePolicyHash(cfg WebsiteMonitorConfig) [32]byte {
	cfg.Schedule = WebsiteSchedule{}
	return websiteConfigHash(cfg)
}

func websiteCycleTimeout(cfg WebsiteMonitorConfig, profiles []*Profile) time.Duration {
	n := enabledWebsites(cfg)
	if n < 1 {
		n = 1
	}
	enabledProfiles := 0
	for _, p := range profiles {
		p.mu.Lock()
		if p.enabled {
			enabledProfiles++
		}
		p.mu.Unlock()
	}
	waves := (n*enabledProfiles + 3) / 4
	if waves < 1 {
		waves = 1
	}
	return time.Duration(cfg.TimeoutSeconds*waves)*time.Second + 15*time.Second
}

func (s *webServer) websiteMonitorAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/website-monitor"), "/")
	switch path {
	case "templates":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, websiteTemplates)
	case "settings":
		if r.Method == http.MethodGet {
			writeJSON(w, s.controller.websiteConfigSnapshot())
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		var request struct {
			Config       WebsiteMonitorConfig `json:"config"`
			Confirm      bool                 `json:"confirm"`
			PreviewToken string               `json:"preview_token"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWebsiteConfigBytes)).Decode(&request) != nil {
			http.Error(w, "invalid website monitor settings", 400)
			return
		}
		if err := validateWebsiteConfig(request.Config); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		oldConfig := s.controller.websiteConfigSnapshot()
		policyChanged := websitePolicyHash(oldConfig) != websitePolicyHash(request.Config)
		if !request.Confirm {
			http.Error(w, "explicit confirmation is required", http.StatusPreconditionRequired)
			return
		}
		if policyChanged {
			s.mu.Lock()
			staged, ok := s.websitePreviews[request.PreviewToken]
			if ok {
				delete(s.websitePreviews, request.PreviewToken)
			}
			s.mu.Unlock()
			if !ok || time.Now().After(staged.Expires) || staged.Hash != websiteConfigHash(request.Config) || staged.BaseHash != websitePolicyHash(oldConfig) {
				http.Error(w, "preview and explicit confirmation are required; preview settings again", http.StatusPreconditionRequired)
				return
			}
		}
		if policyChanged {
			s.controller.websiteRunMu.Lock()
			defer s.controller.websiteRunMu.Unlock()
		}
		if err := s.controller.saveWebsiteMonitor(request.Config); err != nil {
			http.Error(w, "could not persist website monitor settings", 500)
			return
		}
		oldEnabled := oldConfig.Enabled
		s.controller.websiteMu.Lock()
		s.controller.websiteConfig = cloneWebsiteConfig(request.Config)
		s.controller.websitePaused = request.Config.Schedule.Paused
		if request.Config.Enabled && enabledWebsites(request.Config) > 0 && !request.Config.Schedule.Paused {
			s.controller.websiteNextCheck = nextWebsiteTime(time.Now(), request.Config.Schedule)
		} else {
			s.controller.websiteNextCheck = time.Time{}
		}
		if policyChanged {
			s.controller.websiteStatuses = make(map[string]WebsiteProfileStatus)
		}
		s.controller.websiteMu.Unlock()
		select {
		case s.controller.websiteWake <- struct{}{}:
		default:
		}
		if policyChanged {
			for _, p := range s.controller.profilesSnapshot() {
				p.mu.Lock()
				p.websiteSuccessCycles = 0
				p.websiteFailureCycles = 0
				p.websiteRecoveryPending = false
				p.websiteFailures = map[string]int{}
				p.websiteSuccesses = map[string]int{}
				if request.Config.Enabled && enabledWebsites(request.Config) > 0 {
					p.WebsiteState = "PENDING"
					p.RoutingEligible = !websitePolicyApplies(request.Config) && p.Healthy && p.enabled
					p.WebsiteReason = "awaiting scheduled website verification"
				} else {
					p.WebsiteState = "DISABLED"
					p.WebsiteReason = ""
					p.RoutingEligible = p.Healthy && p.enabled
				}
				p.mu.Unlock()
			}
		}
		if policyChanged && request.Config.Enabled && enabledWebsites(request.Config) > 0 {
			runCtx, cancel := context.WithTimeout(r.Context(), websiteCycleTimeout(request.Config, s.controller.profilesSnapshot()))
			defer cancel()
			if err := s.controller.runWebsiteChecksLocked(runCtx, nil); err != nil {
				s.controller.websiteMu.Lock()
				s.controller.websiteLastError = err.Error()
				s.controller.websiteMu.Unlock()
			}
		}
		s.controller.selectProfile()
		if err := s.persistWebsiteState(); err != nil {
			http.Error(w, "website state persistence failed", 500)
			return
		}
		if s.controller.onEvent != nil {
			s.controller.onEvent()
		}
		writeJSON(w, map[string]any{"saved": true, "was_enabled": oldEnabled, "status": s.controller.websiteStatusResponse()})
	case "preview":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		var cfg WebsiteMonitorConfig
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWebsiteConfigBytes)).Decode(&cfg) != nil {
			http.Error(w, "invalid settings", 400)
			return
		}
		if err := validateWebsiteConfig(cfg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		previewCtx, cancel := context.WithTimeout(r.Context(), websiteCycleTimeout(cfg, s.controller.profilesSnapshot()))
		defer cancel()
		result, err := s.controller.previewWebsiteConfig(previewCtx, cfg)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		token, tokenErr := randomToken(32)
		if tokenErr != nil {
			http.Error(w, "preview token generation failed", 500)
			return
		}
		hash := websiteConfigHash(cfg)
		s.mu.Lock()
		if s.websitePreviews == nil {
			s.websitePreviews = map[string]pendingWebsitePreview{}
		}
		for key, value := range s.websitePreviews {
			if time.Now().After(value.Expires) {
				delete(s.websitePreviews, key)
			}
		}
		s.websitePreviews[token] = pendingWebsitePreview{Hash: hash, BaseHash: websitePolicyHash(s.controller.websiteConfigSnapshot()), Expires: time.Now().Add(5 * time.Minute)}
		s.mu.Unlock()
		writeJSON(w, map[string]any{"preview": result, "warning": previewWarning(result), "preview_token": token})
	case "check":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		cfg := s.controller.websiteConfigSnapshot()
		if !cfg.Enabled {
			http.Error(w, "website monitor is disabled", 409)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), websiteCycleTimeout(cfg, s.controller.profilesSnapshot()))
		defer cancel()
		if err := s.controller.runWebsiteChecks(ctx); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		_ = s.persistWebsiteState()
		writeJSON(w, s.controller.websiteStatusResponse())
	case "status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, s.controller.websiteStatusResponse())
	case "history":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		s.controller.websiteMu.RLock()
		h := append([]WebsiteCheckResult(nil), s.controller.websiteHistory...)
		s.controller.websiteMu.RUnlock()
		cutoff := time.Now().Add(-7 * 24 * time.Hour)
		out := h[:0]
		for _, row := range h {
			if row.At.After(cutoff) {
				out = append(out, row)
			}
		}
		writeJSON(w, out)
	default:
		http.NotFound(w, r)
	}
}

func (s *webServer) qualifyAddedProfile(id string) error {
	cfg := s.controller.websiteConfigSnapshot()
	if !websitePolicyApplies(cfg) {
		return nil
	}
	deadline := time.Now().Add(30 * time.Second)
	p := s.controller.findProfile(id)
	if p == nil {
		return errors.New("new profile disappeared")
	}
	for time.Now().Before(deadline) {
		p.mu.Lock()
		ready := p.session != nil
		p.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), websiteCycleTimeout(cfg, []*Profile{p}))
	defer cancel()
	err := s.controller.runWebsiteChecksFor(ctx, []string{id})
	if s.controller.onWebsiteState != nil {
		s.controller.onWebsiteState()
	}
	s.controller.selectProfile()
	return err
}

type WebsitePreview struct {
	ProfileID     string   `json:"profile_id"`
	ProfileName   string   `json:"profile_name"`
	Connectivity  string   `json:"connectivity"`
	WebsiteHealth string   `json:"website_health"`
	Routing       string   `json:"routing_eligibility"`
	Unavailable   []string `json:"unavailable_sites"`
	Reason        string   `json:"reason,omitempty"`
}

func (c *Controller) previewWebsiteConfig(ctx context.Context, cfg WebsiteMonitorConfig) ([]WebsitePreview, error) {
	c.websiteRunMu.Lock()
	defer c.websiteRunMu.Unlock()
	if err := validateWebsiteConfig(cfg); err != nil {
		return nil, err
	}
	websites := make([]Website, 0)
	for _, w := range cfg.Websites {
		if cfg.Enabled && w.Enabled {
			websites = append(websites, w)
		}
	}
	profiles := c.profilesSnapshot()
	out := make([]WebsitePreview, 0, len(profiles))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	rows := map[string][]WebsiteCheckResult{}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	for _, p := range profiles {
		p.mu.Lock()
		enabled := p.enabled
		p.mu.Unlock()
		if !enabled {
			continue
		}
		for _, site := range websites {
			wg.Add(1)
			go func(p *Profile, site Website) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				pc, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				r := c.probeWebsite(pc, p, site, timeout).result
				mu.Lock()
				rows[p.ID] = append(rows[p.ID], r)
				mu.Unlock()
			}(p, site)
		}
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, p := range profiles {
		p.mu.Lock()
		enabled, healthy, name := p.enabled, p.Healthy, p.Name
		p.mu.Unlock()
		if !enabled {
			continue
		}
		eligible := healthy
		websiteState, reason, unavailable := "DISABLED", "", []string(nil)
		if cfg.Enabled && len(websites) > 0 {
			var ok bool
			ok, websiteState, reason, unavailable = websiteProfileEligible(cfg, rows[p.ID], websites)
			eligible = healthy && ok
		}
		if !healthy {
			eligible = false
		}
		state := map[bool]string{true: "ELIGIBLE", false: "BLOCKED"}[eligible]
		out = append(out, WebsitePreview{ProfileID: p.ID, ProfileName: name, Connectivity: map[bool]string{true: "HEALTHY", false: "UNHEALTHY"}[healthy], WebsiteHealth: websiteState, Routing: state, Unavailable: unavailable, Reason: reason})
	}
	return out, nil
}

func previewWarning(preview []WebsitePreview) string {
	eligible := 0
	for _, p := range preview {
		if p.Routing == "ELIGIBLE" {
			eligible++
		}
	}
	if eligible == 0 {
		return "This policy would leave no routing-eligible profiles. Confirm only if fail-closed behavior is intended."
	}
	return fmt.Sprintf("Preview: %d profile(s) would remain routing-eligible.", eligible)
}

func (c *Controller) websiteStatusResponse() map[string]any {
	c.websiteMu.RLock()
	cfg := cloneWebsiteConfig(c.websiteConfig)
	statuses := make([]WebsiteProfileStatus, 0, len(c.websiteStatuses))
	for _, v := range c.websiteStatuses {
		statuses = append(statuses, v)
	}
	next, last, lastErr, paused := c.websiteNextCheck, c.websiteLastCheck, c.websiteLastError, c.websitePaused || c.websiteConfig.Schedule.Paused
	c.websiteMu.RUnlock()
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ProfileID < statuses[j].ProfileID })
	global := map[string]bool{}
	for _, w := range cfg.Websites {
		if !w.Enabled {
			continue
		}
		failed := 0
		for _, s := range statuses {
			for _, u := range s.Unavailable {
				if u == w.Name {
					failed++
				}
			}
		}
		global[w.ID] = len(statuses) > 0 && failed == len(statuses)
	}
	c.websiteMu.RLock()
	history := append([]WebsiteCheckResult(nil), c.websiteHistory...)
	c.websiteMu.RUnlock()
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	seen := map[string]bool{}
	for _, st := range statuses {
		seen[st.ProfileID] = true
	}
	for _, p := range c.profilesSnapshot() {
		p.mu.Lock()
		id, enabled, healthy, last := p.ID, p.enabled, p.Healthy, p.WebsiteLastCheck
		p.mu.Unlock()
		if !enabled || seen[id] {
			continue
		}
		websiteState := "DISABLED"
		routing := "BLOCKED"
		if cfg.Enabled && enabledWebsites(cfg) > 0 {
			websiteState = "PENDING"
		}
		if !websitePolicyApplies(cfg) && healthy {
			routing = "ELIGIBLE"
		}
		statuses = append(statuses, WebsiteProfileStatus{ProfileID: id, Connectivity: map[bool]string{true: "HEALTHY", false: "UNHEALTHY"}[healthy], WebsiteHealth: websiteState, Routing: routing, LastCheck: last, NextCheck: next})
	}
	for i := range statuses {
		var totalLatency int64
		statuses[i].SuccessCount = 0
		statuses[i].ErrorCount = 0
		count := 0
		for _, r := range history {
			if r.ProfileID != statuses[i].ProfileID || r.At.Before(cutoff) {
				continue
			}
			count++
			totalLatency += r.LatencyMS
			if r.Outcome == "PASS" {
				statuses[i].SuccessCount++
			} else {
				statuses[i].ErrorCount++
			}
		}
		if count > 0 {
			statuses[i].AverageLatency = float64(totalLatency) / float64(count)
		}
	}
	return map[string]any{"enabled": cfg.Enabled, "paused": paused, "schedule": cfg.Schedule, "next_check": next, "last_check": last, "last_error": lastErr, "profiles": statuses, "global_site_failures": global, "history_window": "7d"}
}

func (s *webServer) persistWebsiteState() error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	c := s.controller
	c.websiteMu.RLock()
	history := append([]WebsiteCheckResult(nil), c.websiteHistory...)
	c.websiteMu.RUnlock()
	b, err := json.Marshal(struct {
		History []WebsiteCheckResult `json:"history"`
		Updated time.Time            `json:"updated"`
	}{history, time.Now().UTC()})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(s.dataDir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dataDir, ".website-state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dataDir, "website-monitor-state.json"))
}

func (c *Controller) loadWebsiteHistory() error {
	path := filepath.Join(c.websiteDataDir, "website-monitor-state.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32<<20 {
		return errors.New("website state permissions are unsafe")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var state struct {
		History []WebsiteCheckResult `json:"history"`
	}
	if err = json.Unmarshal(b, &state); err != nil {
		return err
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, row := range state.History {
		if row.At.After(cutoff) {
			c.websiteHistory = append(c.websiteHistory, row)
		}
	}
	if len(c.websiteHistory) > maxWebsiteHistory {
		c.websiteHistory = c.websiteHistory[len(c.websiteHistory)-maxWebsiteHistory:]
	}
	return nil
}

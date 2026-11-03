package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type webTestSession struct{ done chan struct{} }

func (s *webTestSession) SOCKSAddr() string     { return "127.0.0.1:9" }
func (s *webTestSession) Done() <-chan struct{} { return s.done }
func (s *webTestSession) Err() error            { return nil }
func (s *webTestSession) Stop(context.Context) error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

type webTestEngine struct{}

func (webTestEngine) Start(context.Context, []byte, string, int) (EngineSession, error) {
	return &webTestSession{done: make(chan struct{})}, nil
}

func TestAdminPasswordStoredAsArgon2HashAndBootstrapIsOneTime(t *testing.T) {
	dir := t.TempDir()
	if err := initializeAdmin(dir, []byte("synthetic-test-passphrase")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(adminPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("admin credential permissions=%o", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(adminPath(dir))
	if bytes.Contains(raw, []byte("synthetic-test-passphrase")) {
		t.Fatal("password stored in plaintext")
	}
	if err := initializeAdmin(dir, []byte("another-synthetic-password")); err == nil {
		t.Fatal("remote/second bootstrap was possible")
	}
}

func TestWebFirstRunSetupConsumesOneTimeToken(t *testing.T) {
	dir := t.TempDir()
	code, err := ensureBootstrapToken(dir)
	if err != nil || code == "" {
		t.Fatalf("create setup token: token=%q err=%v", code, err)
	}
	codeAgain, err := ensureBootstrapToken(dir)
	if err != nil || codeAgain != code {
		t.Fatalf("setup token not stable across restart: err=%v", err)
	}
	web := &webServer{dataDir: dir, sessions: map[string]webSession{}}
	body := fmt.Sprintf(`{"token":%q,"password":"synthetic-test-admin-password"}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(body))
	rec := httptest.NewRecorder()
	web.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first-run Web setup status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(adminPath(dir)); err != nil {
		t.Fatalf("admin credential not created: %v", err)
	}
	if _, err := os.Stat(bootstrapPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("setup token remains after use: %v", err)
	}
	rec = httptest.NewRecorder()
	web.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(body)))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusConflict {
		t.Fatalf("replayed setup token status=%d", rec.Code)
	}
}

func TestProfileMetadataPersistsWithoutConfigSecrets(t *testing.T) {
	dir := t.TempDir()
	c := &Controller{profiles: []*Profile{{ID: "opaque-id", Name: "renamed", Priority: 2, enabled: true, config: []byte(validWG)}}}
	c.healthHistory = []HealthSample{{At: time.Now().UTC(), Profile: "opaque-id", ConnectivityOK: true, ServiceOK: false, Reason: "HTTP 403"}}
	c.appendEvent(ControllerEvent{At: time.Now().UTC(), Kind: "switch", Profile: "opaque-id", Message: "primary → backup"})
	web := &webServer{controller: c, dataDir: dir}
	if err := web.persistState(); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, []byte("SYNTHETIC-TEST")) {
		t.Fatal("private config material persisted in metadata")
	}
	if st, _ := os.Stat(filepath.Join(dir, "state.db")); st.Mode().Perm() != 0600 {
		t.Fatalf("state file mode=%o", st.Mode().Perm())
	}
	loaded := &Profile{ID: "opaque-id", Name: "original", Priority: 1000, enabled: true}
	if err := loadProfileState(dir, []*Profile{loaded}); err != nil {
		t.Fatal(err)
	}
	if loaded.Name != "renamed" || loaded.Priority != 2 || !loaded.enabled {
		t.Fatalf("persisted metadata not restored: %+v", loaded)
	}
	events, err := loadStateEvents(dir)
	if err != nil || len(events) != 1 || events[0].Kind != "switch" {
		t.Fatalf("event history not restored: events=%+v err=%v", events, err)
	}
	history, err := loadHealthHistory(dir)
	if err != nil || len(history) != 1 || !history[0].ConnectivityOK || history[0].ServiceOK {
		t.Fatalf("health history not restored independently: history=%+v err=%v", history, err)
	}
	c.healthHistory = history
	c.rebuildHealthStats()
	if got := c.snapshot().Profiles[0]; got.Availability24H != 100 || got.Service24H != 0 || got.Availability7D != 100 {
		t.Fatalf("availability metrics were not rebuilt from persisted samples: %+v", got)
	}
}

func TestRuntimePriorityOrderAndRestartPersistence(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(profileDir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{profiles: []*Profile{}, ctx: ctx, engine: webTestEngine{}, runtimeDir: filepath.Join(dir, "run"), maxEngines: 8}
	defer func() {
		cancel()
		c.wg.Wait()
	}()
	for i, id := range []string{"first", "second", "third"} {
		config := []byte(strings.Replace(validWG, "172.16.0.2", fmt.Sprintf("172.16.0.%d", i+2), 1))
		path := filepath.Join(profileDir, id+".conf")
		if err := os.WriteFile(path, config, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.addRuntimeProfile(id, id, config, path); err != nil {
			t.Fatal(err)
		}
	}
	assertPriorityOrder := func(profiles []*Profile, want []string) {
		t.Helper()
		got := append([]*Profile(nil), profiles...)
		sort.Slice(got, func(i, j int) bool { return got[i].Priority < got[j].Priority })
		for i, id := range want {
			if got[i].ID != id || got[i].Priority != i {
				t.Fatalf("priority order=%v, want %v (item %d: %+v)", profileIDs(got), want, i, got[i])
			}
		}
	}
	assertPriorityOrder(c.profilesSnapshot(), []string{"first", "second", "third"})
	if err := c.setProfilePriority("third", -1); err != nil {
		t.Fatal(err)
	}
	assertPriorityOrder(c.profilesSnapshot(), []string{"third", "first", "second"})
	if err := c.setProfileEnabled("first", false); err != nil {
		t.Fatal(err)
	}
	web := &webServer{controller: c, dataDir: dir}
	if err := web.persistState(); err != nil {
		t.Fatal(err)
	}
	var settings Settings
	settings.Profiles.Directory = filepath.Join(dir, "missing-configs")
	t.Setenv("AWG_DATA_DIR", dir)
	disabledAfterRestart, err := discover(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadProfileState(dir, disabledAfterRestart); err != nil {
		t.Fatal(err)
	}
	if disabledAfterRestart[1].ID != "first" || disabledAfterRestart[1].enabled {
		t.Fatalf("disabled profile restore changed priority or enabled state: %+v", disabledAfterRestart[1])
	}
	if err := c.setProfileEnabled("first", true); err != nil {
		t.Fatal(err)
	}
	assertPriorityOrder(c.profilesSnapshot(), []string{"third", "first", "second"})
	if err := web.persistState(); err != nil {
		t.Fatal(err)
	}
	// Simulate process restart: discover persisted files, restore metadata, and
	// ensure directory/name order cannot replace the user's selected order.
	restarted, err := discover(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadProfileState(dir, restarted); err != nil {
		t.Fatal(err)
	}
	if got, want := profileIDs(restarted), []string{"third", "first", "second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("restored profile slice order=%v want %v", got, want)
	}
	assertPriorityOrder(restarted, []string{"third", "first", "second"})
	if err := c.removeRuntimeProfile("first"); err != nil {
		t.Fatal(err)
	}
	assertPriorityOrder(c.profilesSnapshot(), []string{"third", "second"})
}

func profileIDs(profiles []*Profile) []string {
	ids := make([]string, len(profiles))
	for i, p := range profiles {
		ids[i] = p.ID
	}
	return ids
}

func TestDiscoverAllowsEmptyConfigDirectories(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "persistent")
	t.Setenv("AWG_DATA_DIR", data)
	var s Settings
	s.Profiles.Directory = filepath.Join(root, "configs")
	profiles, err := discover(s)
	if err != nil {
		t.Fatalf("empty startup is fatal: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("found unexpected profiles: %d", len(profiles))
	}
}

func TestClassifySOCKSReplyCodesSeparately(t *testing.T) {
	tests := map[string]string{
		"SOCKS connect rejected with reply 2": "socks_policy_rejected",
		"SOCKS connect rejected with reply 3": "socks_network_unreachable",
		"SOCKS connect rejected with reply 4": "socks_host_unreachable",
		"SOCKS connect rejected with reply 5": "socks_connection_refused",
	}
	for message, want := range tests {
		if got := classifyHealthError(fmt.Errorf("proxy dial: %s", message)); got != want {
			t.Errorf("classifyHealthError(%q)=%q want %q", message, got, want)
		}
	}
}

func TestDiagnosticResponseOmitsURLPathAndQuery(t *testing.T) {
	c := &Controller{}
	p := &Profile{ID: "test-profile", Healthy: true, State: "HEALTHY", Failures: 1, Successes: 2, LastError: "unchanged"}
	c.active.Store(p)
	result := c.checkURL(context.Background(), p, "https://example.test/private/path?access_token=synthetic-token")
	if _, ok := result["url"]; ok {
		t.Fatal("diagnostic response echoes full URL")
	}
	if result["hostname"] != "example.test" {
		t.Fatalf("hostname=%v", result["hostname"])
	}
	if result["error_type"] != "engine_unavailable" {
		t.Fatalf("missing engine classified as %v", result["error_type"])
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte("synthetic-token")) || bytes.Contains(encoded, []byte("private/path")) {
		t.Fatal("diagnostic response contains URL path/query data")
	}
	if !p.Healthy || p.State != "HEALTHY" || p.Failures != 1 || p.Successes != 2 || p.LastError != "unchanged" || c.active.Load() != p {
		t.Fatal("read-only diagnostic changed health state or global route")
	}
}

func TestConcurrentRuntimeProfileAddRemoveAndSnapshot(t *testing.T) {
	dir := t.TempDir()
	c := &Controller{profiles: []*Profile{}, ctx: context.Background(), engine: webTestEngine{}, runtimeDir: filepath.Join(dir, "run"), maxEngines: 64}
	var added sync.WaitGroup
	for i := 0; i < 12; i++ {
		added.Add(1)
		go func(i int) {
			defer added.Done()
			id := fmt.Sprintf("profile-%02d", i)
			config := []byte(strings.Replace(validWG, "172.16.0.2", fmt.Sprintf("172.16.0.%d", i+2), 1))
			if _, err := c.addRuntimeProfile(id, id, config, filepath.Join(dir, id+".conf")); err != nil {
				t.Errorf("add: %v", err)
			}
		}(i)
	}
	added.Wait()
	if got := len(c.profilesSnapshot()); got != 12 {
		t.Fatalf("added %d profiles, want 12", got)
	}
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 20; j++ {
				_ = c.snapshot()
			}
		}()
	}
	for _, p := range c.profilesSnapshot() {
		if err := c.removeRuntimeProfile(p.ID); err != nil {
			t.Errorf("remove %s: %v", p.ID, err)
		}
	}
	readers.Wait()
	if got := len(c.profilesSnapshot()); got != 0 {
		t.Fatalf("remaining profiles=%d", got)
	}
}

func TestUploadRejectsTraversalInvalidLargeAndSymlinkStorage(t *testing.T) {
	testUpload := func(t *testing.T, server *webServer, filename string, data []byte) int {
		t.Helper()
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		part, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write(data)
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/api/profiles", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-CSRF-Token", "csrf")
		req.AddCookie(&http.Cookie{Name: "awg_session", Value: "session"})
		res := httptest.NewRecorder()
		server.handler().ServeHTTP(res, req)
		return res.Code
	}
	newServer := func(dir string) *webServer {
		c := &Controller{profiles: []*Profile{}, ctx: context.Background(), engine: webTestEngine{}, runtimeDir: filepath.Join(dir, "run"), maxEngines: 8}
		return &webServer{controller: c, dataDir: dir, sessions: map[string]webSession{"session": {csrf: "csrf", expires: time.Now().Add(time.Hour)}}}
	}
	t.Run("path traversal and invalid configuration", func(t *testing.T) {
		dir := t.TempDir()
		server := newServer(dir)
		t.Cleanup(func() {
			for _, p := range server.controller.profilesSnapshot() {
				_ = server.controller.removeRuntimeProfile(p.ID)
				_ = os.Remove(p.path)
			}
		})
		if code := testUpload(t, server, "../escape.conf", []byte(validWG)); code != 201 {
			t.Fatalf("sanitized traversal upload status=%d", code)
		}
		if got := len(server.controller.profilesSnapshot()); got != 1 {
			t.Fatalf("sanitized traversal profile count=%d", got)
		}
		if code := testUpload(t, server, "invalid.conf", []byte("[Interface]\nPrivateKey=bad\n")); code != 400 {
			t.Fatalf("invalid config status=%d", code)
		}
		if _, err := os.Stat(filepath.Join(dir, "escape.conf")); !os.IsNotExist(err) {
			t.Fatal("traversal wrote outside profile storage")
		}
	})
	t.Run("size limit", func(t *testing.T) {
		if code := testUpload(t, newServer(t.TempDir()), "oversized.conf", bytes.Repeat([]byte("x"), maxProfileBytes+1)); code != 413 {
			t.Fatalf("oversized upload status=%d", code)
		}
	})
	t.Run("symlink storage directory", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dir, "profiles")); err != nil {
			t.Fatal(err)
		}
		if code := testUpload(t, newServer(dir), "safe.conf", []byte(validWG)); code != 500 {
			t.Fatalf("symlink storage status=%d", code)
		}
		entries, _ := os.ReadDir(outside)
		if len(entries) != 0 {
			t.Fatal("upload wrote through a symlink")
		}
	})
}

func TestUploadWithRepeatedClientFilenameCreatesDistinctProfiles(t *testing.T) {
	dir := t.TempDir()
	c := &Controller{profiles: []*Profile{}, ctx: context.Background(), engine: webTestEngine{}, runtimeDir: filepath.Join(dir, "run"), maxEngines: 8}
	server := &webServer{controller: c, dataDir: dir, sessions: map[string]webSession{"session": {csrf: "csrf", expires: time.Now().Add(time.Hour)}}}
	t.Cleanup(func() {
		for _, p := range c.profilesSnapshot() {
			_ = c.removeRuntimeProfile(p.ID)
			_ = os.Remove(p.path)
		}
	})
	upload := func(address string) int {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		part, _ := mw.CreateFormFile("file", "same-name.conf")
		config := strings.Replace(validWG, "172.16.0.2", address, 1)
		_, _ = part.Write([]byte(config))
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/api/profiles", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-CSRF-Token", "csrf")
		req.AddCookie(&http.Cookie{Name: "awg_session", Value: "session"})
		res := httptest.NewRecorder()
		server.handler().ServeHTTP(res, req)
		if res.Code != 201 {
			t.Fatalf("upload status=%d body=%s", res.Code, res.Body.String())
		}
		var profile profilePublic
		if err := json.Unmarshal(res.Body.Bytes(), &profile); err != nil {
			t.Fatal(err)
		}
		return len(profile.ID)
	}
	if upload("172.16.0.2") == 0 || upload("172.16.0.3") == 0 {
		t.Fatal("opaque IDs are empty")
	}
	if got := len(c.profilesSnapshot()); got != 2 {
		t.Fatalf("same client filename replaced profile; count=%d", got)
	}
}

func TestAdminAuthenticationCSRFAndProxyPortIsolation(t *testing.T) {
	dir := t.TempDir()
	if err := initializeAdmin(dir, []byte("synthetic-test-passphrase")); err != nil {
		t.Fatal(err)
	}
	settings := Settings{}
	settings.Failover.CheckTimeout = time.Second
	c := &Controller{settings: settings, profiles: []*Profile{}, ctx: context.Background(), engine: webTestEngine{}, runtimeDir: filepath.Join(dir, "runtime")}
	web := &webServer{controller: c, dataDir: dir, sessions: map[string]webSession{}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	web.handler().ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("anonymous admin API status=%d", rr.Code)
	}
	originRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	originRequest.Host = "awg-switcher.local"
	originRequest.Header.Set("Origin", "https://attacker.example")
	originResponse := httptest.NewRecorder()
	web.handler().ServeHTTP(originResponse, originRequest)
	if originResponse.Code != 403 {
		t.Fatalf("cross-origin request status=%d", originResponse.Code)
	}
	body := strings.NewReader(`{"password":"incorrect-synthetic-password"}`)
	rr = httptest.NewRecorder()
	web.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/login", body))
	if rr.Code != 401 {
		t.Fatalf("wrong password status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	web.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"password":"synthetic-test-passphrase"}`)))
	if rr.Code != 200 {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	var login struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(rr.Body.Bytes(), &login) != nil || login.CSRF == "" {
		t.Fatal("login did not return CSRF token")
	}
	cookie := rr.Result().Cookies()[0]
	req = httptest.NewRequest(http.MethodPost, "/api/profiles", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	web.handler().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("mutating API without CSRF status=%d", rr.Code)
	}
	proxy := httptest.NewRecorder()
	applicationHandler(c).ServeHTTP(proxy, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if proxy.Code == 200 || strings.Contains(proxy.Body.String(), `"profiles"`) {
		t.Fatalf("proxy listener exposed status API: %d", proxy.Code)
	}
}

func TestProfileUploadUsesOpaqueIDMasksSecretsAndRuntimeAddsWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	_ = initializeAdmin(dir, []byte("synthetic-test-passphrase"))
	c := &Controller{settings: Settings{}, profiles: []*Profile{}, ctx: context.Background(), engine: webTestEngine{}, runtimeDir: filepath.Join(dir, "run")}
	c.settings.Failover.CheckTimeout = time.Second
	c.prepareContextForWebTest()
	web := &webServer{controller: c, dataDir: dir, sessions: map[string]webSession{"session": {csrf: "csrf", expires: time.Now().Add(time.Hour)}}}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "friendly-name.conf")
	_, _ = part.Write([]byte(validWG))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/profiles", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", "csrf")
	req.AddCookie(&http.Cookie{Name: "awg_session", Value: "session"})
	rr := httptest.NewRecorder()
	web.handler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("upload status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(c.profilesSnapshot()) != 1 {
		t.Fatal("uploaded profile did not enter live controller")
	}
	p := c.profilesSnapshot()[0]
	if p.ID == "friendly-name.conf" {
		t.Fatal("client filename was trusted as profile ID")
	}
	if _, err := os.Stat(p.path); err != nil {
		t.Fatalf("persistent imported config missing: %v", err)
	}
	st, _ := os.Stat(p.path)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("profile file mode=%o", st.Mode().Perm())
	}
	replacement := strings.Replace(validWG, "MTU = 1280", "MTU = 1360", 1)
	replaceReq := httptest.NewRequest(http.MethodPut, "/api/profiles/"+p.ID+"/config", strings.NewReader(replacement))
	replaceReq.AddCookie(&http.Cookie{Name: "awg_session", Value: "session"})
	replaceReq.Header.Set("X-CSRF-Token", "csrf")
	replaceRes := httptest.NewRecorder()
	web.handler().ServeHTTP(replaceRes, replaceReq)
	if replaceRes.Code != 200 {
		t.Fatalf("config replace status=%d body=%s", replaceRes.Code, replaceRes.Body.String())
	}
	saved, _ := os.ReadFile(p.path)
	if !strings.Contains(string(saved), "MTU = 1360") {
		t.Fatal("replacement was not atomically persisted")
	}
	config := httptest.NewRecorder()
	web.handler().ServeHTTP(config, requestWithCookie(http.MethodGet, "/api/profiles/"+p.ID+"/config", "session"))
	if strings.Contains(config.Body.String(), "<SYNTHETIC-TEST-NOT-SECRET>") {
		t.Fatal("private key leaked in safe config view")
	}
	if !strings.Contains(config.Body.String(), "[REDACTED]") {
		t.Fatal("safe config view did not mask key")
	}
	var duplicateBody bytes.Buffer
	duplicateWriter := multipart.NewWriter(&duplicateBody)
	duplicatePart, _ := duplicateWriter.CreateFormFile("file", "same-config-different-name.conf")
	_, _ = duplicatePart.Write([]byte(replacement))
	_ = duplicateWriter.Close()
	duplicateRequest := httptest.NewRequest(http.MethodPost, "/api/profiles", &duplicateBody)
	duplicateRequest.Header.Set("Content-Type", duplicateWriter.FormDataContentType())
	duplicateRequest.Header.Set("X-CSRF-Token", "csrf")
	duplicateRequest.AddCookie(&http.Cookie{Name: "awg_session", Value: "session"})
	duplicateResponse := httptest.NewRecorder()
	web.handler().ServeHTTP(duplicateResponse, duplicateRequest)
	if duplicateResponse.Code != http.StatusConflict || len(c.profilesSnapshot()) != 1 {
		t.Fatalf("duplicate profile import status=%d profiles=%d body=%s", duplicateResponse.Code, len(c.profilesSnapshot()), duplicateResponse.Body.String())
	}
	profileFiles, err := filepath.Glob(filepath.Join(dir, "profiles", "*.conf"))
	if err != nil || len(profileFiles) != 1 {
		t.Fatalf("duplicate import left an orphaned managed file: files=%v err=%v", profileFiles, err)
	}
	response := httptest.NewRecorder()
	web.handler().ServeHTTP(response, requestWithCookie(http.MethodGet, "/api/profiles", "session"))
	if strings.Contains(response.Body.String(), "<SYNTHETIC-TEST-NOT-SECRET>") {
		t.Fatal("private key leaked in profile JSON")
	}
	_ = c.removeRuntimeProfile(p.ID)
	_ = os.Remove(p.path)
}

func requestWithCookie(method, path, id string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.AddCookie(&http.Cookie{Name: "awg_session", Value: id})
	return r
}
func (c *Controller) prepareContextForWebTest() {
	c.ctx = context.Background()
	c.prepareProfileForTest()
}
func (c *Controller) prepareProfileForTest() {
	if c.engine == nil {
		c.engine = webTestEngine{}
	}
}

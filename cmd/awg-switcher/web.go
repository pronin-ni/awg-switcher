package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

//go:embed web/*
var webFiles embed.FS

const maxProfileBytes = 1 << 20

type adminCredential struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}
type webSession struct {
	csrf    string
	expires time.Time
}
type webServer struct {
	controller       *Controller
	dataDir          string
	mu               sync.Mutex
	persistMu        sync.Mutex
	sessions         map[string]webSession
	failures         []time.Time
	loginActive      int
	configGenMu      sync.Mutex
	configGenLoaded  bool
	configGen        configGeneratorSettings
	configGenRun     sync.Mutex
	configGenStarts  []time.Time
	websitePreviews  map[string]pendingWebsitePreview
	autoMu           sync.RWMutex
	autoConfig       AutoReplenishmentConfig
	autoState        AutoReplenishmentState
	autoRunning      bool
	autoTaskRunning  bool
	autoNextCheck    time.Time
	autoWake         chan struct{}
	autoRunMu        sync.Mutex
	autoRunFunc      func(context.Context, configGeneratorSettings, string, int) (generatedConfigResponse, error)
	autoVerifyFunc   func(context.Context, *Profile, bool) ([]WebsiteCheckResult, error)
	autoCleanupCheck func(context.Context, *Profile) healthResult
	autoNow          func() time.Time
	autoCancel       context.CancelFunc
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func adminPath(dir string) string     { return filepath.Join(dir, "admin.json") }
func bootstrapPath(dir string) string { return filepath.Join(dir, "bootstrap.token") }

// ensureBootstrapToken creates a one-time setup credential on an empty data
// volume. It is logged so Portainer users can complete setup without shell
// access; successful setup removes it permanently.
func ensureBootstrapToken(dir string) (string, error) {
	if _, err := os.Lstat(adminPath(dir)); err == nil {
		return "", nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	path := bootstrapPath(dir)
	if b, err := os.ReadFile(path); err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", errors.New("bootstrap token file permissions are unsafe")
		}
		return strings.TrimSpace(string(b)), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	token, err := randomToken(24)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(f, token+"\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", errors.New("cannot persist setup token")
	}
	return token, nil
}

// initializeAdmin is intentionally a local CLI operation; there is no remote first-user registration.
func initializeAdmin(dir string, password []byte) error {
	if len(password) < 14 || len(password) > 1024 {
		return errors.New("password must contain 14..1024 bytes")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create data directory")
	}
	path := adminPath(dir)
	if _, err := os.Lstat(path); err == nil {
		return errors.New("administrator is already initialized")
	} else if !os.IsNotExist(err) {
		return errors.New("cannot inspect administrator state")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return errors.New("secure random source unavailable")
	}
	hash := argon2.IDKey(password, salt, 3, 64*1024, 2, 32)
	b, err := json.Marshal(adminCredential{Salt: base64.RawStdEncoding.EncodeToString(salt), Hash: base64.RawStdEncoding.EncodeToString(hash)})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("administrator state already exists or cannot be written")
	}
	_, werr := f.Write(append(b, '\n'))
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return errors.New("administrator state write failed")
	}
	if cerr != nil {
		return errors.New("administrator state close failed")
	}
	return nil
}
func adminPasswordCLI(dir string) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("create-admin requires an interactive terminal")
	}
	fmt.Fprint(os.Stderr, "New administrator password (14+ characters): ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return errors.New("password input failed")
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return errors.New("password input failed")
	}
	if subtle.ConstantTimeCompare(first, second) != 1 {
		return errors.New("passwords do not match")
	}
	return initializeAdmin(dir, first)
}

func (s *webServer) credential() (adminCredential, error) {
	var c adminCredential
	path := adminPath(s.dataDir)
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return c, errors.New("administrator credential file permissions are unsafe")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}
func (s *webServer) authenticated(r *http.Request) (webSession, bool) {
	cookie, err := r.Cookie("awg_session")
	if err != nil {
		return webSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[cookie.Value]
	if !ok || time.Now().After(session.expires) {
		delete(s.sessions, cookie.Value)
		return webSession{}, false
	}
	return session, true
}
func (s *webServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/api/setup/status", s.setupStatus)
	mux.HandleFunc("/api/setup", s.setup)
	mux.HandleFunc("/assets.css", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/assets.css")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/app.js")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/setup.js", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/setup.js")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/diagnostics.js", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/diagnostics.js")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/config-generator.js", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/config-generator.js")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/website-monitor.js", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/website-monitor.js")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/auto-replenishment.js", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/auto-replenishment.js")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/automation-page.js", func(w http.ResponseWriter, r *http.Request) {
		b, e := webFiles.ReadFile("web/automation-page.js")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/api/session", s.session)
	mux.HandleFunc("/api/status", s.requireAuth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.controller.snapshot()) }))
	mux.HandleFunc("/api/events", s.requireAuth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.controller.snapshot().Events) }))
	mux.HandleFunc("/api/profiles", s.requireAuth(s.profiles))
	mux.HandleFunc("/api/profiles/", s.requireAuth(s.profile))
	mux.HandleFunc("/api/diagnostics/check", s.requireAuth(s.diagnosticCheck))
	mux.HandleFunc("/api/website-monitor/", s.requireAuth(s.websiteMonitorAPI))
	mux.HandleFunc("/api/diagnostics/debug", s.requireAuth(s.networkDebug))
	mux.HandleFunc("/api/support-bundle", s.requireAuth(s.downloadSupportBundle))
	mux.HandleFunc("/api/config-generator/settings", s.requireAuth(s.configGeneratorSettingsHandler))
	mux.HandleFunc("/api/config-generator/test", s.requireAuth(s.testConfigGeneratorHandler))
	mux.HandleFunc("/api/config-generator/generate", s.requireAuth(s.generateWarpProfilesHandler))
	mux.HandleFunc("/api/auto-replenishment/", s.requireAuth(s.automationAPI))
	mux.HandleFunc("/logout", s.requireAuth(s.logout))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := webFiles.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "UI unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(b)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || !strings.EqualFold(u.Host, r.Host) || (u.Scheme != "http" && u.Scheme != "https") {
				http.Error(w, "origin rejected", http.StatusForbidden)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *webServer) setupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := os.Lstat(adminPath(s.dataDir))
	writeJSON(w, map[string]bool{"initialized": err == nil})
}

func (s *webServer) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	cutoff := time.Now().Add(-10 * time.Minute)
	kept := s.failures[:0]
	for _, at := range s.failures {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	s.failures = kept
	if len(s.failures) >= 8 || s.loginActive >= 2 {
		s.mu.Unlock()
		http.Error(w, "setup temporarily rate limited", http.StatusTooManyRequests)
		return
	}
	s.loginActive++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.loginActive--; s.mu.Unlock() }()
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || len(input.Password) < 14 || len(input.Password) > 1024 {
		http.Error(w, "invalid setup request or password length", http.StatusBadRequest)
		return
	}
	token, err := os.ReadFile(bootstrapPath(s.dataDir))
	if err != nil || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(token))), []byte(input.Token)) != 1 {
		s.mu.Lock()
		s.failures = append(s.failures, time.Now())
		s.mu.Unlock()
		http.Error(w, "invalid setup code", http.StatusUnauthorized)
		return
	}
	if err := initializeAdmin(s.dataDir, []byte(input.Password)); err != nil {
		http.Error(w, "administrator setup failed", http.StatusConflict)
		return
	}
	if err := os.Remove(bootstrapPath(s.dataDir)); err != nil {
		http.Error(w, "administrator initialized but setup token cleanup failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"initialized": true})
}
func (s *webServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			sess, ok := s.authenticated(r)
			if !ok {
				http.Error(w, "authentication required", 401)
				return
			}
			if r.Header.Get("X-CSRF-Token") == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
				http.Error(w, "csrf validation failed", 403)
				return
			}
		} else if _, ok := s.authenticated(r); !ok {
			http.Error(w, "authentication required", 401)
			return
		}
		next(w, r)
	}
}
func (s *webServer) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	s.mu.Lock()
	cutoff := time.Now().Add(-10 * time.Minute)
	kept := s.failures[:0]
	for _, t := range s.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.failures = kept
	if len(s.failures) >= 8 || s.loginActive >= 2 {
		s.mu.Unlock()
		http.Error(w, "login temporarily rate limited", 429)
		return
	}
	s.loginActive++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.loginActive--; s.mu.Unlock() }()
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var input struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	cred, err := s.credential()
	salt, e1 := base64.RawStdEncoding.DecodeString(cred.Salt)
	expected, e2 := base64.RawStdEncoding.DecodeString(cred.Hash)
	valid := false
	if err == nil && e1 == nil && e2 == nil && len(input.Password) <= 1024 {
		got := argon2.IDKey([]byte(input.Password), salt, 3, 64*1024, 2, uint32(len(expected)))
		valid = subtle.ConstantTimeCompare(got, expected) == 1
	}
	if !valid {
		s.mu.Lock()
		s.failures = append(s.failures, time.Now())
		s.mu.Unlock()
		http.Error(w, "invalid credentials", 401)
		return
	}
	id, err := randomToken(32)
	if err != nil {
		http.Error(w, "session unavailable", 500)
		return
	}
	csrf, err := randomToken(32)
	if err != nil {
		http.Error(w, "session unavailable", 500)
		return
	}
	s.mu.Lock()
	s.sessions[id] = webSession{csrf: csrf, expires: time.Now().Add(12 * time.Hour)}
	s.failures = nil
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "awg_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestSecure(r), Expires: time.Now().Add(12 * time.Hour)})
	writeJSON(w, map[string]string{"csrf": csrf})
}
func requestSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(os.Getenv("AWG_COOKIE_SECURE"), "true")
}
func (s *webServer) session(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	sess, ok := s.authenticated(r)
	if !ok {
		http.Error(w, "authentication required", 401)
		return
	}
	writeJSON(w, map[string]string{"csrf": sess.csrf})
}
func (s *webServer) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	cookie, _ := r.Cookie("awg_session")
	s.mu.Lock()
	if cookie != nil {
		delete(s.sessions, cookie.Value)
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "awg_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestSecure(r), MaxAge: -1})
	w.WriteHeader(204)
}

var safeUploadName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,79}\.conf$`)

func safeStoredProfilePath(dataDir string, p *Profile) (string, error) {
	if p == nil || p.ID == "" || filepath.Base(p.ID) != p.ID || strings.ContainsAny(p.ID, `/\\`) {
		return "", errors.New("invalid profile id")
	}
	root, err := filepath.Abs(filepath.Join(dataDir, "profiles"))
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("profile directory is unsafe")
	}
	path, err := filepath.Abs(p.path)
	if err != nil || path != filepath.Join(root, p.ID+".conf") {
		return "", errors.New("profile path is outside the managed directory")
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("profile file is unsafe")
	}
	return path, nil
}

func (s *webServer) profiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		views := []profilePublic{}
		cfg := s.autoConfigSnapshot()
		for _, p := range s.controller.profilesSnapshot() {
			view := profileView(p)
			view.AutoDeleteActive = cfg.Enabled && cfg.AutoDeleteFailed
			view.AutoDeleteAfterHours = cfg.AutoDeleteAfterHours
			views = append(views, view)
		}
		writeJSON(w, views)
	case http.MethodPost:
		s.upload(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (s *webServer) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxProfileBytes+64*1024)
	if err := r.ParseMultipartForm(maxProfileBytes); err != nil {
		http.Error(w, "upload exceeds size limit or is malformed", 413)
		return
	}
	defer r.MultipartForm.RemoveAll()
	f, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing config file", 400)
		return
	}
	defer f.Close()
	if !safeUploadName.MatchString(filepath.Base(header.Filename)) || filepath.Base(header.Filename) != header.Filename {
		http.Error(w, "filename must be a simple .conf name", 400)
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProfileBytes+1))
	if err != nil || len(b) > maxProfileBytes {
		http.Error(w, "config exceeds 1 MiB", 413)
		return
	}
	normalized, err := normalizeWG(b)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	id, path, err := storeImportedProfile(s.dataDir, normalized)
	if err != nil {
		http.Error(w, "profile storage unavailable", 500)
		return
	}
	name := strings.TrimSuffix(filepath.Base(header.Filename), filepath.Ext(header.Filename))
	p, err := s.controller.addRuntimeProfile(id, name, normalized, path)
	if err != nil {
		_ = os.Remove(path)
		if errors.Is(err, errProfileConfigDuplicate) {
			http.Error(w, "an identical profile configuration already exists", http.StatusConflict)
			return
		}
		http.Error(w, "profile was stored but could not be started", 503)
		return
	}
	p.mu.Lock()
	p.Origin = ProfileOriginManualImport
	p.mu.Unlock()
	if err := s.qualifyAddedProfile(id); err != nil {
		http.Error(w, "profile imported but website monitor check could not complete", 503)
		return
	}
	if err = s.persistState(); err != nil {
		http.Error(w, "profile loaded but state persistence failed", 500)
		return
	}
	w.WriteHeader(201)
	writeJSON(w, profileView(p))
}
func (s *webServer) profile(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "profiles" {
		http.NotFound(w, r)
		return
	}
	id := parts[2]
	if len(parts) == 4 && parts[3] == "config" && r.Method == http.MethodGet {
		p := s.controller.findProfile(id)
		if p == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(maskConfig(p.config))
		return
	}
	if len(parts) == 4 && parts[3] == "config" && r.Method == http.MethodPut {
		p := s.controller.findProfile(id)
		if p == nil {
			http.NotFound(w, r)
			return
		}
		root := filepath.Clean(filepath.Join(s.dataDir, "profiles"))
		if !strings.HasPrefix(filepath.Clean(p.path), root+string(os.PathSeparator)) {
			http.Error(w, "filesystem profiles are read-only", 409)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxProfileBytes))
		if err != nil {
			http.Error(w, "config exceeds 1 MiB", 413)
			return
		}
		normalized, err := normalizeWG(body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		info, err := os.Lstat(p.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			http.Error(w, "profile storage path is unsafe", 409)
			return
		}
		tmp, err := os.CreateTemp(root, ".replace-*.tmp")
		if err != nil {
			http.Error(w, "profile storage unavailable", 500)
			return
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)
		if err = tmp.Chmod(0600); err == nil {
			_, err = tmp.Write(normalized)
		}
		if e := tmp.Close(); err == nil {
			err = e
		}
		if err != nil {
			http.Error(w, "profile write failed", 500)
			return
		}
		if err = os.Rename(tmpName, p.path); err != nil {
			http.Error(w, "profile replacement failed", 500)
			return
		}
		if err = s.controller.replaceRuntimeConfig(id, normalized); err != nil {
			http.Error(w, "profile update failed", 409)
			return
		}
		writeJSON(w, profileView(p))
		return
	}
	if len(parts) == 4 && parts[3] == "check" && r.Method == http.MethodPost {
		p := s.controller.findProfile(id)
		if p == nil {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.controller.settings.Failover.CheckTimeout)
		defer cancel()
		res := s.controller.check(ctx, p)
		s.controller.recordHealth(p, res)
		s.controller.selectProfile()
		writeJSON(w, map[string]any{"profile_id": id, "healthy": res.Healthy, "reason": res.Reason, "latency_ms": res.Latency.Milliseconds()})
		return
	}
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}
	p := s.controller.findProfile(id)
	if p == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req struct {
			Name                *string `json:"name"`
			Priority            *int    `json:"priority"`
			Enabled             *bool   `json:"enabled"`
			Primary             bool    `json:"primary"`
			Automatic           bool    `json:"automatic"`
			AutoDeleteProtected *bool   `json:"auto_delete_protected"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		if req.Name != nil {
			if strings.TrimSpace(*req.Name) == "" || len(*req.Name) > 80 {
				http.Error(w, "invalid profile name", 400)
				return
			}
			p.mu.Lock()
			p.Name = *req.Name
			p.mu.Unlock()
		}
		if req.Priority != nil {
			if err := s.controller.setProfilePriority(id, *req.Priority); err != nil {
				http.Error(w, "profile priority update failed", 409)
				return
			}
		}
		if req.Enabled != nil {
			if err := s.controller.setProfileEnabled(id, *req.Enabled); err != nil {
				http.Error(w, "profile operation failed", 409)
				return
			}
		}
		if req.AutoDeleteProtected != nil {
			p.mu.Lock()
			if p.Origin != ProfileOriginAutoGenerated {
				p.mu.Unlock()
				http.Error(w, "automatic deletion protection is only available for generated profiles", http.StatusConflict)
				return
			}
			p.AutoDeleteProtected = *req.AutoDeleteProtected
			p.mu.Unlock()
		}
		if req.Primary {
			if err := s.controller.selectManual(id, 30*time.Minute); err != nil {
				http.Error(w, "profile is not healthy", 409)
				return
			}
		}
		if req.Automatic {
			s.controller.clearManual()
		}
		if err := s.persistState(); err != nil {
			http.Error(w, "state persistence failed", 500)
			return
		}
		writeJSON(w, profileView(p))
	case http.MethodDelete:
		if _, pathErr := safeStoredProfilePath(s.dataDir, p); pathErr != nil {
			http.Error(w, "filesystem profiles are read-only", 409)
			return
		}
		if err := s.controller.removeRuntimeProfileWith(id, nil, func(profile *Profile) error {
			path, err := safeStoredProfilePath(s.dataDir, profile)
			if err != nil {
				return err
			}
			return os.Remove(path)
		}); err != nil {
			http.Error(w, "profile could not be removed", 409)
			return
		}
		if err := s.persistState(); err != nil {
			http.Error(w, "profile removed but state could not be saved", 500)
			return
		}
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (s *webServer) diagnosticCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		ID        string `json:"id"`
		URL       string `json:"url"`
		FullCheck bool   `json:"full_check"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	u, e := url.ParseRequestURI(req.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		http.Error(w, "a valid HTTPS URL is required", 400)
		return
	}
	p := s.controller.findProfile(req.ID)
	if p == nil {
		http.Error(w, "profile not found", 404)
		return
	}
	targets := []string{u.String()}
	if req.FullCheck {
		targets = []string{"https://api.ipify.org", "https://www.facebook.com/", "https://api.radarr.video/v1/search?q=xt"}
	}
	results := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		targetURL, _ := url.Parse(target)
		trace := newNetworkTrace(p, targetURL.Hostname())
		ctx := withNetworkTrace(r.Context(), trace)
		result := s.controller.checkURL(ctx, p, target)
		finished := trace.snapshot()
		s.controller.debugNetworkTrace(finished)
		results = append(results, result)
	}
	if req.FullCheck {
		writeJSON(w, map[string]any{"profile_id": p.ID, "results": results})
		return
	}
	writeJSON(w, results[0])
}

func (s *webServer) networkDebug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.Method == http.MethodGet {
		enabled, until := s.controller.networkDebugState()
		writeJSON(w, map[string]any{"enabled": enabled, "expires_at": until, "duration_seconds": 600})
		return
	}
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	until := s.controller.setNetworkDebug(request.Enabled)
	writeJSON(w, map[string]any{"enabled": request.Enabled, "expires_at": until})
}

func (s *webServer) downloadSupportBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="awg-switcher-support.json"`)
	writeJSON(w, s.controller.supportBundle())
}

type profileState struct {
	Name                  string    `json:"name"`
	Priority              int       `json:"priority"`
	Enabled               bool      `json:"enabled"`
	LastError             string    `json:"last_error,omitempty"`
	AutoGenerated         bool      `json:"auto_generated,omitempty"`
	AutoCandidate         bool      `json:"auto_candidate,omitempty"`
	AutoVerified          bool      `json:"auto_verified,omitempty"`
	AutoVerifyReason      string    `json:"auto_verify_reason,omitempty"`
	Origin                string    `json:"origin,omitempty"`
	AutoDeleteProtected   bool      `json:"auto_delete_protected,omitempty"`
	AutoUnavailableSince  time.Time `json:"auto_unavailable_since,omitempty"`
	AutoUnavailableChecks int       `json:"auto_unavailable_checks,omitempty"`
}

func (s *webServer) persistState() error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	items := map[string]profileState{}
	for _, p := range s.controller.profilesSnapshot() {
		p.mu.Lock()
		items[p.ID] = profileState{Name: p.Name, Priority: p.Priority, Enabled: p.enabled, LastError: p.LastError, AutoGenerated: p.AutoGenerated, AutoCandidate: p.AutoCandidate, AutoVerified: p.AutoVerified, AutoVerifyReason: p.AutoVerifyReason, Origin: p.Origin, AutoDeleteProtected: p.AutoDeleteProtected, AutoUnavailableSince: p.AutoUnavailableSince, AutoUnavailableChecks: p.AutoUnavailableChecks}
		p.mu.Unlock()
	}
	s.controller.eventsMu.Lock()
	events := append([]ControllerEvent(nil), s.controller.events...)
	s.controller.eventsMu.Unlock()
	s.controller.healthMu.Lock()
	health := append([]HealthSample(nil), s.controller.healthHistory...)
	s.controller.healthMu.Unlock()
	data, err := json.Marshal(struct {
		Profiles map[string]profileState `json:"profiles"`
		Events   []ControllerEvent       `json:"events"`
		Health   []HealthSample          `json:"health_history,omitempty"`
		Updated  time.Time               `json:"updated"`
	}{items, events, health, time.Now().UTC()})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(s.dataDir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dataDir, ".state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(data, '\n'))
	}
	if e := tmp.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(s.dataDir, "state.db"))
}
func loadProfileState(dir string, profiles []*Profile) error {
	path := filepath.Join(dir, "state.db")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("profile state file permissions are unsafe")
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state struct {
		Profiles map[string]profileState `json:"profiles"`
	}
	if json.Unmarshal(b, &state) != nil {
		return errors.New("profile state database is invalid")
	}
	for _, p := range profiles {
		if v, ok := state.Profiles[p.ID]; ok {
			p.Name = v.Name
			p.Priority = v.Priority
			p.enabled = v.Enabled
			p.LastError = v.LastError
			p.AutoGenerated = v.AutoGenerated
			p.AutoCandidate = v.AutoCandidate
			p.AutoVerified = v.AutoVerified
			p.AutoVerifyReason = v.AutoVerifyReason
			p.Origin = v.Origin
			// AutoGenerated was only written by the built-in automatic WARP
			// generator in older state.db versions, so it is trustworthy legacy
			// provenance. Never infer origin from a profile name.
			if p.Origin == "" && v.AutoGenerated {
				p.Origin = ProfileOriginAutoGenerated
			}
			if p.Origin != ProfileOriginManualImport && p.Origin != ProfileOriginAutoGenerated {
				p.Origin = ""
			}
			p.AutoGenerated = v.AutoGenerated || p.Origin == ProfileOriginAutoGenerated
			p.AutoDeleteProtected = v.AutoDeleteProtected
			p.AutoUnavailableSince = v.AutoUnavailableSince
			p.AutoUnavailableChecks = v.AutoUnavailableChecks
			if !v.Enabled {
				p.State = "DISABLED"
			}
		}
	}
	sort.SliceStable(profiles, func(i, j int) bool {
		return profiles[i].Priority < profiles[j].Priority
	})
	return nil
}
func loadStateEvents(dir string) ([]ControllerEvent, error) {
	path := filepath.Join(dir, "state.db")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("profile state file permissions are unsafe")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state struct {
		Events []ControllerEvent `json:"events"`
	}
	if json.Unmarshal(b, &state) != nil {
		return nil, errors.New("profile state database is invalid")
	}
	if len(state.Events) > 200 {
		state.Events = state.Events[len(state.Events)-200:]
	}
	return state.Events, nil
}

func loadHealthHistory(dir string) ([]HealthSample, error) {
	path := filepath.Join(dir, "state.db")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("profile state file permissions are unsafe")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state struct {
		Health []HealthSample `json:"health_history"`
	}
	if json.Unmarshal(b, &state) != nil {
		return nil, errors.New("profile state database is invalid")
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	history := state.Health[:0]
	for _, sample := range state.Health {
		if sample.At.After(cutoff) {
			history = append(history, sample)
		}
	}
	if len(history) > 100000 {
		history = history[len(history)-100000:]
	}
	return history, nil
}

type profilePublic struct {
	Name                  string    `json:"name"`
	ID                    string    `json:"id"`
	Priority              int       `json:"priority"`
	State                 string    `json:"state"`
	Healthy               bool      `json:"healthy"`
	ConnectivityHealthy   bool      `json:"connectivity_healthy"`
	ServiceHealthy        bool      `json:"service_healthy"`
	Availability24H       float64   `json:"availability_24h"`
	Availability7D        float64   `json:"availability_7d"`
	ServiceHealth24H      float64   `json:"service_health_24h"`
	ServiceHealth7D       float64   `json:"service_health_7d"`
	WebsiteHealth         string    `json:"website_health"`
	WebsiteReason         string    `json:"website_reason,omitempty"`
	RoutingEligible       bool      `json:"routing_eligible"`
	WebsiteLastCheck      time.Time `json:"website_last_check,omitempty"`
	AutoGenerated         bool      `json:"auto_generated,omitempty"`
	AutoCandidate         bool      `json:"auto_candidate,omitempty"`
	AutoVerified          bool      `json:"auto_verified,omitempty"`
	AutoVerifyReason      string    `json:"auto_verify_reason,omitempty"`
	LastError             string    `json:"last_error,omitempty"`
	LastCheck             time.Time `json:"last_check,omitempty"`
	LastSuccess           time.Time `json:"last_success,omitempty"`
	LatencyMS             int64     `json:"latency_ms"`
	Restarts              int       `json:"restarts"`
	Source                string    `json:"source"`
	Endpoint              string    `json:"endpoint,omitempty"`
	MTU                   string    `json:"mtu,omitempty"`
	Addresses             []string  `json:"addresses,omitempty"`
	ExternalIP            string    `json:"external_ip,omitempty"`
	Protocol              string    `json:"protocol"`
	Origin                string    `json:"origin,omitempty"`
	AutoDeleteProtected   bool      `json:"auto_delete_protected,omitempty"`
	AutoUnavailableSince  time.Time `json:"auto_unavailable_since,omitempty"`
	AutoUnavailableChecks int       `json:"auto_unavailable_checks,omitempty"`
	AutoDeleteActive      bool      `json:"auto_delete_active,omitempty"`
	AutoDeleteAfterHours  int       `json:"auto_delete_after_hours,omitempty"`
}

func profileView(p *Profile) profilePublic {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := profilePublic{Name: p.Name, ID: p.ID, Priority: p.Priority, State: p.State, Healthy: p.Healthy, ConnectivityHealthy: p.ConnectivityOK, ServiceHealthy: p.ServiceHealthy, Availability24H: p.Availability24H, Availability7D: p.Availability7D, ServiceHealth24H: p.Service24H, ServiceHealth7D: p.Service7D, WebsiteHealth: p.WebsiteState, WebsiteReason: p.WebsiteReason, RoutingEligible: p.RoutingEligible, WebsiteLastCheck: p.WebsiteLastCheck, AutoGenerated: p.AutoGenerated, AutoCandidate: p.AutoCandidate, AutoVerified: p.AutoVerified, AutoVerifyReason: p.AutoVerifyReason, LastError: p.LastError, LastCheck: p.LastCheck, LastSuccess: p.LastSuccess, LatencyMS: p.HealthLatencyMS, Restarts: p.Restarts, Source: "filesystem", ExternalIP: p.ExternalIP, Protocol: "WireGuard", Origin: p.Origin, AutoDeleteProtected: p.AutoDeleteProtected, AutoUnavailableSince: p.AutoUnavailableSince, AutoUnavailableChecks: p.AutoUnavailableChecks}
	if strings.Contains(p.path, "/data/profiles/") {
		v.Source = "imported"
	}
	for _, line := range strings.Split(string(p.config), "\n") {
		k, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "endpoint":
			v.Endpoint = strings.TrimSpace(val)
		case "mtu":
			v.MTU = strings.TrimSpace(val)
		case "address":
			v.Addresses = strings.Split(strings.TrimSpace(val), ",")
		case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "headerprotectionkey":
			v.Protocol = "AmneziaWG (userspace)"
		}
	}
	return v
}
func maskConfig(config []byte) []byte {
	var out []string
	for _, line := range strings.Split(string(config), "\n") {
		trim := strings.TrimSpace(line)
		key, _, ok := strings.Cut(trim, "=")
		if ok {
			k := strings.ToLower(strings.TrimSpace(key))
			if strings.Contains(k, "key") || strings.Contains(k, "password") || strings.Contains(k, "token") || strings.Contains(k, "secret") {
				line = key + " = [REDACTED]"
			}
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Engine interface {
	Start(context.Context, []byte, string, int) (EngineSession, error)
}

type EngineSession interface {
	SOCKSAddr() string
	Done() <-chan struct{}
	Err() error
	Stop(context.Context) error
}

type ProcessEngine struct {
	Binary     string
	RuntimeDir string
}

type processSession struct {
	cmd        *exec.Cmd
	addr       string
	configPath string
	done       chan struct{}
	mu         sync.RWMutex
	err        error
}

func (s *processSession) SOCKSAddr() string     { return s.addr }
func (s *processSession) Done() <-chan struct{} { return s.done }
func (s *processSession) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}

func (e ProcessEngine) Start(ctx context.Context, config []byte, socks string, slot int) (EngineSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.Binary == "" {
		return nil, errors.New("engine binary not configured")
	}
	if err := os.MkdirAll(e.RuntimeDir, 0700); err != nil {
		return nil, errors.New("runtime directory unavailable")
	}
	path := filepath.Join(e.RuntimeDir, fmt.Sprintf("profile-%d.conf", slot))
	data := strings.TrimSpace(string(config)) + fmt.Sprintf("\n\n[Socks5]\nBindAddress = %s\n", socks)
	tmp, err := os.CreateTemp(e.RuntimeDir, fmt.Sprintf("profile-%d-*.tmp", slot))
	if err != nil {
		return nil, errors.New("runtime config creation failed")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.WriteString(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, errors.New("runtime config write failed")
	}
	if err = os.Rename(tmpName, path); err != nil {
		return nil, errors.New("runtime config install failed")
	}
	cmd := exec.Command(e.Binary, "-c", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard // Engine output is not trusted to be secret-free.
	if err = cmd.Start(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("engine process start failed: %w", err)
	}
	s := &processSession{cmd: cmd, addr: socks, configPath: path, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		_ = os.Remove(s.configPath)
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		close(s.done)
	}()
	return s, nil
}

func (s *processSession) Stop(ctx context.Context) error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	select {
	case <-s.done:
		return nil
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		_ = s.cmd.Process.Kill()
		<-s.done
		return ctx.Err()
	case <-timer.C:
		_ = s.cmd.Process.Kill()
		select {
		case <-s.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func retryDelay(now time.Time, history []time.Time) (time.Duration, []time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	kept := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) > 5 {
		return 5 * time.Minute, kept
	}
	seconds := 1 << min(len(kept)-1, 6)
	if seconds > 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second, kept
}

func (c *Controller) supervise(ctx context.Context, p *Profile, slot int) {
	defer c.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		p.State = "STARTING"
		p.mu.Unlock()
		session, err := c.engine.Start(ctx, p.config, p.socks, slot)
		if err != nil {
			p.mu.Lock()
			p.Restarts++
			p.State = "COOLDOWN"
			p.LastError = "engine start failed"
			delay, history := retryDelay(time.Now(), p.restartTimes)
			p.restartTimes = history
			p.mu.Unlock()
			slog.Warn("engine restart scheduled", "profile", p.Name, "delay", delay)
			if !waitContext(ctx, delay) {
				return
			}
			continue
		}
		p.mu.Lock()
		p.session = session
		p.socks = session.SOCKSAddr()
		p.State = "CONNECTING"
		p.LastError = ""
		p.mu.Unlock()
		c.selectProfile()
		select {
		case <-ctx.Done():
			stopCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			_ = session.Stop(stopCtx)
			cancel()
			p.mu.Lock()
			p.session = nil
			p.State = "DISABLED"
			p.Healthy = false
			p.mu.Unlock()
			return
		case <-session.Done():
			p.mu.Lock()
			p.session = nil
			p.Healthy = false
			p.Successes = 0
			p.Failures = c.settings.Failover.FailureThreshold
			p.State = "UNHEALTHY"
			p.LastError = "engine process exited"
			p.Restarts++
			delay, history := retryDelay(time.Now(), p.restartTimes)
			p.restartTimes = history
			p.mu.Unlock()
			if p.transport != nil {
				p.transport.CloseIdleConnections()
			}
			if session.Err() != nil {
				slog.Warn("engine exited", "profile", p.Name)
			}
			c.selectProfile()
			if !waitContext(ctx, delay) {
				return
			}
		case <-p.restartReq:
			stopCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			_ = session.Stop(stopCtx)
			cancel()
			p.mu.Lock()
			p.session = nil
			p.Healthy = false
			p.State = "COOLDOWN"
			p.Restarts++
			delay, history := retryDelay(time.Now(), p.restartTimes)
			p.restartTimes = history
			p.mu.Unlock()
			if p.transport != nil {
				p.transport.CloseIdleConnections()
			}
			c.selectProfile()
			if !waitContext(ctx, delay) {
				return
			}
		}
	}
}

func waitContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

# Validation report

Validation date: 2026-11-01. This report omits credentials, VPN keys, raw public IPs, and full logs. The VPS validation used a separate feature-test container/network with admin and proxy ports bound to loopback only. The existing baseline project and NAS services were not changed.

## Feature candidate local checks

- `go test ./... -count=1` — PASS (auth/CSRF, empty profile directory, config validation, traversal/symlink/size checks, secret masking, profile state/event persistence, runtime CRUD, concurrency and proxy fail-closed coverage).
- `go test -race ./... -count=1` — PASS.
- `go vet ./...` — PASS.
- `govulncheck@v1.2.0 ./...` — no reachable vulnerability in called code; it reports one required module advisory in `golang.org/x/crypto` as not reachable.
- Bun browser bundling — PASS; plain embedded JS/CSS/HTML with no frontend packages.
- Docker Compose base and LAN override validation — PASS.
- `go-licenses v1.6.0 check` — PASS for MIT/ISC/Apache-2.0/BSD-3-Clause source dependencies. The Linux/amd64 candidate image SBOM has 26 components with reviewed license mappings.
- Gitleaks full Git history — PASS, zero findings. `creds/` remains ignored and excluded from Docker build context.

## Docker E2E

- Linux/amd64 image built locally as development candidate `awg-switcher:webui-dev` (image ID `sha256:8e87f7f89d2136eaf78d49db9a92a500f9a45e8792137c146a0de2880e96bb8b`; saved archive SHA-256 `0de4405654a82947db5a93d37cb273997caa5029c15eefcff0e85f5e32e872a6`). No GHCR image was published.
- Read-only container, empty config directory — UI remained available, unauthenticated admin returned 401, CSRF mutation returned 403, proxy readiness returned 503, and proxy CONNECT failed closed with 503.
- Zero-config first-run Docker E2E on an empty named volume — one-time setup code, browser setup API, embedded UI assets, administrator login, persisted admin credential, and login after container restart all passed. Empty bind-mount setup wrote only the mode-0600 admin file to the host. Docker healthcheck reports process liveness while no VPN is configured, leaving proxy readiness fail-closed.
- Local synthetic-profile E2E — upload, opaque profile ID, safe config masking/no secret in profile JSON, rename/priority, atomic replacement, delete, and metadata restoration after container restart — PASS.
- Candidate image layer scan — 33 files; zero config/key/settings paths and zero matches for locally supplied PrivateKeys. Trivy license scanner found zero license findings.
- Trivy vulnerability scan — `GO-2026-5932` in `golang.org/x/crypto v0.58.0` appears against each of the two Go binaries (two duplicate image findings); no fix version was listed. `govulncheck` says the advisory is not reachable from imported/called code. This remains a security-review gate, not silently suppressed.
- GitHub Actions run `41287868835` at current tested head `afa7174` — PASS for `tests-and-license` and `dependency-review`; `publish-ghcr` was skipped by the explicit release gates. The dependency-review job initially exposed non-SPDX `UNKNOWN`/`NOASSERTION` entries and a disabled repository dependency graph. The policy now uses SPDX identifiers, and GitHub dependency alerts/graph were enabled rather than removing the check. A Gitleaks Action run on an intermediate head raced with a subsequent PR update and tried scanning a not-yet-fetched head; CI now runs pinned Gitleaks CLI directly against the checked-out history. Node 24 versions are used for checkout, Go setup, dependency review, and artifact upload.

## Dedicated VPS live validation

- Feature candidate ran as a separate container and Docker network on the dedicated Ubuntu 24.04 amd64 VPS. Admin and proxy host mappings were `127.0.0.1` only. Existing `awg-switcher-e2e` baseline container was left running and unchanged.
- Both supplied real profiles started independent engines and reached `HEALTHY`; direct SOCKS5 probes to `api.ipify.org` returned HTTPS 200 with verified TLS for each wireproxy listener.
- Web UI upload of a real `.conf` from the local ignored `creds/` directory returned 201 with a generated opaque ID. Explicit profile checks became successful; HTTPS diagnostics via that imported engine returned HTTP 200/TLS verified. The imported test profile was deleted afterward.
- HTTPS diagnostics for `https://api.radarr.video/v1/search?q=xt` timed out for both exits after SOCKS negotiation. `https://radarr.servarr.com/v1/ping` timed out on one exit; the other failed during SOCKS connect with a generic connection error (no SOCKS reply code was available to classify further). Direct per-engine SOCKS probes also failed to complete those Radarr requests. By contrast, ipify succeeded over both tunnels. Direct checks outside the VPN completed TLS: from the workstation, `api.radarr.video/` returned 404 and `radarr.servarr.com/` 200; from the VPS host network, both tested Radarr paths returned HTTP 200. Thus the failure is specific to the VPN tunnel/exit path or filtering of those exits, not general VPS or destination availability. The tunnel attempts did not obtain an HTTP response or complete TLS. No HTTP 403 was observed, so this is not an application-level authorization result.
- Failover evidence did not depend on changing public IP: the active wireproxy child was paused in the isolated container; the controller marked it unhealthy, selected the other profile ID, and two new HTTPS requests through the HTTP proxy succeeded during the transition. The supervisor restarted/recovered the paused profile, selected it again after recovery checks, and ten HTTPS proxy requests succeeded during recovery.
- After replacing the candidate container while preserving its protected data directory, both real profiles recovered and the persisted event feed was restored. Local Docker E2E separately verified UI metadata survives container restart.

## Remaining release gates

- Radarr endpoint compatibility is unresolved for these VPN exits. Direct VPS-host HTTPS returns HTTP 200 for the tested paths, while the same paths fail over each configured VPN exit; ipify works through those exits. This localizes the issue to VPN/tunnel egress or exit-IP filtering, but cannot distinguish peer configuration from provider-side policy. A different exit/peer or provider clarification is needed; no direct-network fallback was added because it would violate fail-closed routing. Sonarr was not separately validated.
- Both real profiles have the same previously observed egress-IP fingerprint; the live failover proof therefore uses selected profile IDs, stopped/restarted engine process, and successful new proxy requests instead of IP change.
- The upstream wireproxy release tag is unsigned (source commit is pinned and checked); this is a provenance concern, not by itself a license incompatibility. Individual CA certificate terms and legal sufficiency still require human review.
- PR #1 was squash-merged into `main` as `85044df`; CI also passed on `df5acd6`. The new Portainer zero-config changes are being validated in the current development branch and have not yet published an image. No production NAS deployment was performed.

**Overall: DEVELOPMENT. Prior VPN engine/failover validation passed on the isolated VPS. The new empty-volume/admin onboarding passed local Docker E2E; it still needs CI and integration with a new real profile. Radarr compatibility through the tested VPN exits remains unresolved; do not bypass VPN fail-closed routing.**

## Pre-first-run fixes (2026-11-01)

- Runtime-import priorities now start at `0` for the first profile and append subsequent profiles by upload order. UI up/down moves insert at the requested position and renumber priorities uniquely; deleting a profile compacts ranks without changing relative order. Disabling/re-enabling preserves order. Saved priorities and enabled state are restored and the discovered profile slice is sorted by restored priority on startup.
- Added `TestRuntimePriorityOrderAndRestartPersistence` covering order, priority movement, disable/restore, deletion, and simulated rediscovery after restart.
- Added `node --check` for `web/setup.js` and a Playwright Chromium smoke test in CI. The local real-browser smoke passed against a Docker image and empty named volume: setup token, admin creation/login, dashboard, two `.conf` uploads, listing, UI reorder, restart, login, and restored profile order.
- Local Docker hardened bind-mount check passed with the production capability set, read-only root, tmpfs and `no-new-privileges`: the container created its own bootstrap file without manual directory creation/ownership/mode changes; PID 1 effective UID/GID was `10001:10001`.
- TOS 6 read-only diagnostics and a disposable capability/ACL probe are documented in README. This environment is not a TerraMaster TOS 6 host, so TOS ACL behavior itself was not observed.
- At the time of the original candidate validation, no `creds/` directory or accessible VPS connection details were available, so no new real-profile VPN, failover/recovery, egress, or per-exit Radarr checks were run then. See the WARP generator live follow-up below for the later VPS validation. Do not infer that the tested VPN exits can reach Radarr; the fail-closed behavior remains unchanged.

## WARP generator live follow-up (2026-11-01)

- SSH host identity was verified against the VPS owner-confirmed ED25519 fingerprint before password authentication. The existing `awg-switcher-e2e-awg-switcher-1` container was not restarted or modified.
- Built upstream `amnezia-config-gen` from pinned commit `cebc09e46f636f74e6ddc4ec1dae94b8d3046e12` on the VPS and queried its live `/api/warp` API. One real config each was generated for AWG 2.0, 3.0 and 3.1 using `endpointMode=hostname`, `ipv6=false`, `cps=static`; each decoded to exactly `AllowedIPs = 0.0.0.0/0` and a hostname Endpoint.
- Each generated config passed the VPS `awg-wireproxy` `-n` parser check. Then each was run in a separate temporary wireproxy container on the existing E2E Docker network, using the app image’s wireproxy binary and UID/GID 10001:10001. A SOCKS5-routed HTTPS request to `https://api.ipify.org` succeeded for all three versions.
- Generated config files were kept mode `0600` and removed after the probe. Temporary generator/tunnel containers and the test-built generator image were removed. Final VPS check: the original E2E container remained `running`, `healthy`, restart count `0`; it was the only running container. This validates the real generator and VPN protocol configs, but is not a full authenticated Web UI/API import smoke test of commit `761f651`.
- No WARP private keys, raw config contents, or egress IPs are included in this report. The registrations were real Cloudflare WARP registrations; no automatic retries were made.

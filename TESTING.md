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
- PR #1 was squash-merged into `main` as `85044df`. Feature CI passed at `afa7174`; main-branch CI is running on the merge commit. No production NAS deployment or GHCR publication was performed.

**Overall: feature merged to `main`, validated locally and on the isolated VPS; main-branch CI is running. Public release remains blocked by Radarr compatibility through tested exits and the separately documented provenance/certificate review.**

# Validation report

This report contains no VPN keys, raw public addresses, SSH credentials, or full live logs. Validation was performed on 2026-11-01 against the dedicated Ubuntu 24.04 x86_64 test VPS. No NAS or pre-existing service/container was involved.

## Local checks

- `go test ./... -count=1` — PASS, including HTTP methods/body forwarding, large streaming, HTTPS CONNECT through the application mux, SOCKS hostname routing, fail-closed, and fake-engine failover/recovery tests.
- `go test -race ./... -count=1` — PASS.
- `go vet ./...` — PASS.
- `govulncheck@v1.2.0 ./...` — PASS, no known Go vulnerabilities reported.
- `docker-compose -f docker-compose.yml config -q` — PASS.
- Profile parser — both locally supplied profiles passed `normalizeWG`; filenames and profile contents were not printed.
- Secret checks — Gitleaks v8.30.1 scanned the current six-commit Git history: zero findings. A sanitized source tree excluding ignored `creds/` also had zero findings. The three generic-key matches when scanning the entire local worktree were all confined to ignored files under `creds/`; none are tracked or included in the image/build context.

## Dedicated VPS

- Ubuntu 24.04, x86_64/amd64, `/dev/net/tun` present. The chosen userspace engine does not need the host TUN device.
- Docker Engine 29.1.3 and Compose 2.40.3 installed on the dedicated VPS; initial Docker container count was zero.
- Local Linux/amd64 Docker build from the secret-free build context — PASS, using wireproxy v2.1.0 source commit `02588433b6328171b594d76f3f16bd3404258a83`, Go 1.27.3, and security-updated x/net v0.62.0 / x/crypto v0.58.0. `govulncheck` reports no reachable vulnerabilities in wireproxy. Trivy reports no x/net advisories; its one remaining finding is the legacy OpenPGP advisory at x/crypto module level. Trivy's license scanner reports Go license data as “not scanned”; the explicit `go-licenses` checks pass for both source graphs.
- Final image SBOM — generated from the final built image with Syft v1.55.0, then supplemented with the audited license mapping and packaged Alpine CA-bundle license. `image-sbom.cdx.json` contains 23 components. Trivy v0.76.1 did not attach license identifiers to the Go binaries; the explicit `go-licenses` source audits pass, but legal/provenance review remains open.
- Saved-image layer check — 31 files scanned; zero `.conf`/key/settings files and zero exact private-key matches against the two supplied profiles.
- Isolated Compose project `awg-switcher-e2e` — config validation and startup PASS; final candidate container reached healthy state; two separate supplied real profiles reached `HEALTHY` concurrently.
- `api.ipify.org` HTTPS through the primary — HTTP 200. Pausing the primary engine caused the controller to fail over; a new HTTPS request through the proxy succeeded through the backup. Both supplied exits returned the **same** public egress-IP fingerprint, so a live IP change cannot be proven with these profiles.
- Primary engine recovery — PASS: supervisor restarted the interrupted process, it passed recovery probes, selection returned to primary, and HTTPS continued through the proxy.
- Pausing both live engines produced `UNHEALTHY` state for both profiles; an actual HTTP CONNECT request returned `503 Service Unavailable`. The controller restarted the engines and the test project recovered to healthy state. Fake-engine tests also assert zero DIRECT-target hits.
- `https://api.radarr.video/v1/search?q=xt` and `https://radarr.servarr.com/v1/ping` did not complete CONNECT from these live profiles (proxy CONNECT 503). The failures were not interpreted as VPN health failures after other HTTPS routes succeeded. Cloudflare trace was also unavailable from this test route. These resource-compatibility checks remain open.
- First container start exposed a test-only bind-mount permissions mistake (`settings.yaml` was owner-readable only by root). After setting the mounted settings/configs readable by UID 10001 within the VPS's root-protected project directory, startup and health checks passed. NAS installation instructions now include ownership/mode requirements.

## Release gates still open

- The generated container SBOM/license supplement is available, but image license scanner output did not independently resolve Go package license IDs. The notice files were verified by the saved-image file/layer scan only for inclusion, not legal sufficiency.
- The upstream release tag is unsigned; the source commit is pinned and checked during the source build, but tag authenticity remains a provenance risk.
- The two supplied profiles share an egress-IP fingerprint, so the requested live primary-IP-to-backup-IP change is not proven. Radarr/Sonarr-related endpoints also remain unverified from these exits.
- GitHub Actions has not yet run for these changes; full-history secret scanning is configured and the current local history/source scans are clean.
- Production NAS deployment and GHCR publication were not performed. The license review remains **LICENSE REVIEW REQUIRED**.

**Overall: BLOCKED for production release.** The implementation is ready for continued isolated live validation; the findings above prevent a production-ready claim.

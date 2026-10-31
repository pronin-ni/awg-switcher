# Validation report

This report contains no VPN keys, raw public addresses, SSH credentials, or full live logs. Validation was performed on 2026-10-31 against the dedicated Ubuntu 24.04 x86_64 test VPS. No NAS or pre-existing service/container was involved.

## Local checks

- `go test ./... -count=1` — PASS, including HTTP methods/body forwarding, large streaming, HTTPS CONNECT through the application mux, SOCKS hostname routing, fail-closed, and fake-engine failover/recovery tests.
- `go test -race ./... -count=1` — PASS.
- `go vet ./...` — PASS.
- `govulncheck@v1.2.0 ./...` — PASS, no known Go vulnerabilities reported.
- `docker-compose -f docker-compose.yml config -q` — PASS.
- Profile parser — both locally supplied profiles passed `normalizeWG`; filenames and profile contents were not printed.
- Secret checks — Gitleaks v8.24.3 scanned a sanitized source tree: zero findings. `creds/` was excluded from the source archive and Docker build context. There was no local Git history; the target GitHub repository was empty before publication, so no prior history needed scanning.

## Dedicated VPS

- Ubuntu 24.04, x86_64/amd64, `/dev/net/tun` present. The chosen userspace engine does not need the host TUN device.
- Docker Engine 29.1.3 and Compose 2.40.3 installed on the dedicated VPS; initial Docker container count was zero.
- Linux/amd64 Docker build from the secret-free archive — PASS. The upstream wireproxy archive checksum matched the pinned SHA-256. Image runs as UID/GID 10001 with a read-only root filesystem, dropped capabilities, and no-new-privileges.
- Final image SBOM — generated from the built image with Syft v1.55.0 (release checksum verified), then supplemented with the already-reviewed license mapping and the packaged Alpine CA-bundle license. `image-sbom.cdx.json` contains 23 components. Trivy v0.76.1 (release checksum verified) inspected 20 Go package entries but did not attach license identifiers; this is why the license review remains open rather than treating an empty scanner result as clearance.
- Saved-image layer check — 31 files scanned; zero `.conf`/key/settings files and zero exact private-key matches against the two supplied profiles.
- Isolated Compose project `awg-switcher-e2e` — config validation and startup PASS; container reached healthy state; two separate supplied real profiles reached `HEALTHY` concurrently.
- `api.ipify.org` HTTPS through the primary — HTTP 200. On stopping the primary's engine process, the controller selected the backup and the HTTPS request continued through the proxy. The tested primary and backup returned the **same** public egress-IP fingerprint, so an IP change between these two profiles could not be demonstrated. This is a limitation of the supplied exits, not evidence of distinct public egress.
- Primary engine recovery — PASS: supervisor restarted the interrupted process, the profile passed recovery probes, and selection returned to primary.
- Stopping both test engine processes made active profile empty; an HTTPS CONNECT attempt returned proxy CONNECT status 503. No DIRECT retry is implemented. Fake-engine tests additionally assert that an instrumented DIRECT target receives zero requests.
- `https://api.radarr.video/v1/search?q=xt` and `https://radarr.servarr.com/v1/ping` did not complete CONNECT from these live profiles (proxy CONNECT 503). The failures were not interpreted as VPN health failures after other HTTPS routes succeeded. Cloudflare trace was also unavailable from this test route. These resource-compatibility checks remain open.
- First container start exposed a test-only bind-mount permissions mistake (`settings.yaml` was owner-readable only by root). After setting the mounted settings/configs readable by UID 10001 within the VPS's root-protected project directory, startup and health checks passed. NAS installation instructions now include ownership/mode requirements.

## Release gates still open

- The generated container SBOM/license supplement is available, but image license scanner output did not independently resolve Go package license IDs. The notice files were verified by the saved-image file/layer scan only for inclusion, not legal sufficiency.
- The upstream release tag is unsigned; its hash and embedded build revision are pinned/checked, but a source-to-binary build comparison remains incomplete.
- The two supplied profiles share an egress-IP fingerprint, so the requested live primary-IP-to-backup-IP change is not proven. Radarr/Sonarr-related endpoints also remain unverified from these exits.
- Gitleaks is configured in GitHub Actions. A local source pattern scan was clean, but no Gitleaks executable was available locally. The existing GitHub repository was empty before the initial source commit; full-history scan will run in GitHub Actions after push.
- Production NAS deployment and GHCR publication were not performed. The license review remains **LICENSE REVIEW REQUIRED**.

**Overall: BLOCKED for production release.** The implementation is ready for continued isolated live validation; the findings above prevent a production-ready claim.

# Licensing release gate

**Status: LICENSE REVIEW REQUIRED** (as of 2026-11-01; Web UI feature branch).

## Completed checks

- AWG Switcher original code is explicitly MIT-licensed in `LICENSE`.
- Exact `awg-wireproxy` v2.1.0 annotated tag resolves to commit `02588433b6328171b594d76f3f16bd3404258a83`; its ISC license and upstream copyrights are retained. The Dockerfile now builds from that exact source commit using Go 1.27.3, rather than shipping the upstream prebuilt binary (which was built with vulnerable Go 1.27.1). The tag remains unsigned; the commit is verified explicitly during build.
- The wireproxy source build pins security updates `golang.org/x/net v0.62.0` and `golang.org/x/crypto v0.58.0` without changing engine version. `govulncheck` reports no reachable vulnerabilities in `./cmd/wireproxy`; Trivy still reports the legacy OpenPGP advisory because its module-level detector does not establish whether that package is linked. This finding remains documented for review.
- Exact AmneziaWG Go dependency v3.1.20260828 resolves to `b5928efb6ca19f0153958460c3d141f04abc5c2e`; the MIT license text is bundled.
- Go dependency licenses were inventoried for the Linux/amd64 source graph with `google/go-licenses v1.6.0`; reports are in `licenses/go-modules.csv` and `licenses/wireproxy-go-modules.csv`. All required license files are copied to `/usr/share/licenses/awg-switcher/` in the image recipe.
- New admin dependencies are `golang.org/x/crypto v0.58.0` (Argon2id) and `golang.org/x/term v0.47.0` (no-echo terminal password entry), both BSD-3-Clause; their source license text and CSV inventory are included. The embedded UI uses no third-party libraries, package manager, external fonts, or telemetry.
- Persistent `state.db` is an atomic JSON metadata document, not SQLite; VPN configuration bytes remain in separate protected `0600` files and are excluded from metadata/logs.
- The apparent GPL result for `kernel.org/.../libcap/psx v1.2.77` was manually checked. Its source explicitly says `BSD-3-Clause OR GPL-2.0-only`; this project selects BSD-3-Clause and preserves the complete upstream `License` file. CI contains a narrow exception for only this exact package/license pair and rejects other unreviewed licenses.
- Alpine's ca-certificate package index identifies `ca-certificates-bundle` as `MPL-2.0 AND MIT`; the runtime image recipe pins package version `20261020-r0`, and MPL text is bundled.
- Repository includes MIT, third-party notices, dependency inventory, Go-module CycloneDX SBOM, contribution/security policies, license scanning, secret scanning, dependency review, and image SBOM generation in CI.

## Remaining blockers / risks

1. The upstream wireproxy tag is unsigned (`verified=false`). Docker verifies the exact commit and compiles from its source using the pinned Go 1.27.3 toolchain, but the unsigned-tag authenticity risk remains.
2. The feature candidate was built for Linux/amd64, exercised in local Docker E2E, scanned with Syft/Trivy, and tested on the isolated VPS with two real profiles, real-profile UI import, failover and recovery. `image-sbom.cdx.json` contains 26 license-mapped components. Trivy reports `GO-2026-5932` twice (once per Go binary) for `golang.org/x/crypto v0.58.0`; no fixed version is reported, and `govulncheck` identifies no reachable call path. The advisory is specifically for the unused, unmaintained `golang.org/x/crypto/openpgp` packages; retain this finding for security review. GitHub Actions run `41287496504` passed both jobs at `00c3b30`; CI at current head is in progress.
3. Real `.conf` secrets are present in ignored `creds/` and remain untouched. Gitleaks detected only three generic-key patterns in those ignored files; a sanitized source tree and all Git history scanned with zero findings. `.gitignore` and `.dockerignore` exclude `creds/`; never force-add those files. Rotate keys if they were ever published elsewhere.
4. Alpine APK package signature/index validation is built into the package manager. The CA bundle's licensing data and package version are pinned; individual certificate-authority terms have not been reviewed.
5. Container base-image digests and Go toolchain image digests are pinned in `Dockerfile`; the successful VPS build confirms the pinned references and CA package version are available for Linux/amd64.
6. No legal counsel has reviewed the result. Automated license detection does not constitute legal advice.

The upstream tag signature is a supply-chain provenance concern, not by itself a license incompatibility. Given the remaining provenance/CA/legal review and pending candidate image audit, the project is not cleared for public binary/container release. GHCR publishing requires repository variables `ALLOW_PUBLIC_RELEASE=true`, `LICENSE_REVIEW_PASSED=true`, and `LIVE_VALIDATION_PASSED=true`; leave them unset until all technical and legal review gates pass.

# Licensing release gate

**Status: LICENSE REVIEW REQUIRED** (as of 2026-10-31).

## Completed checks

- AWG Switcher original code is explicitly MIT-licensed in `LICENSE`.
- Exact `awg-wireproxy` v2.1.0 annotated tag resolves to commit `02588433b6328171b594d76f3f16bd3404258a83`; its ISC license and upstream copyrights are retained. The downloaded Linux/amd64 binary's embedded Go build metadata identifies the same source revision, Go 1.27.1, and `CGO_ENABLED=0`; its archive SHA-256 is verified and pinned in `Dockerfile`.
- Exact AmneziaWG Go dependency v3.1.20260828 resolves to `b5928efb6ca19f0153958460c3d141f04abc5c2e`; the MIT license text is bundled.
- Go dependency licenses were inventoried for the Linux/amd64 source graph with `google/go-licenses v1.6.0`; reports are in `licenses/go-modules.csv` and `licenses/wireproxy-go-modules.csv`. All required license files are copied to `/usr/share/licenses/awg-switcher/` in the image recipe.
- The apparent GPL result for `kernel.org/.../libcap/psx v1.2.77` was manually checked. Its source explicitly says `BSD-3-Clause OR GPL-2.0-only`; this project selects BSD-3-Clause and preserves the complete upstream `License` file. CI contains a narrow exception for only this exact package/license pair and rejects other unreviewed licenses.
- Alpine's ca-certificate package index identifies `ca-certificates-bundle` as `MPL-2.0 AND MIT`; the runtime image recipe pins package version `20261020-r0`, and MPL text is bundled.
- Repository includes MIT, third-party notices, dependency inventory, Go-module CycloneDX SBOM, contribution/security policies, license scanning, secret scanning, dependency review, and image SBOM generation in CI.

## Remaining blockers / risks

1. The upstream wireproxy tag is unsigned (`verified=false`). Embedded build metadata matches the tag commit and the artifact hash is pinned, but no independent reproducible build comparison was completed.
2. The Linux/amd64 image was built and exercised on the isolated VPS. Syft generated a 23-component image SBOM, supplemented with the previously audited license inventory; Trivy inspected 20 Go package entries but did not independently attach license identifiers. A saved-image layer check found no profile/config/key files or matches for either supplied private key. The scanner does not independently confirm license sufficiency; CI has not executed on GitHub.
3. Local real `.conf` secrets were detected in `creds/` and left untouched. The directory is now explicitly excluded by `.gitignore` and `.dockerignore`; because the workspace has no Git metadata, historical secret exposure cannot be checked. Do not force-add these files; rotate the keys if they were ever published.
4. Alpine APK package signature/index validation is built into the package manager, but the exact archive contents and any certificate-authority-specific conditions have not been manually inspected in the built image. The CA bundle's licensing data and package version are pinned; this does not replace per-certificate review.
5. Container base-image digests and Go toolchain image digests are pinned in `Dockerfile`; the successful VPS build confirms the pinned references and CA package version are available for Linux/amd64.
6. No legal counsel has reviewed the result. Automated license detection does not constitute legal advice.

Given these unresolved checks, the project is not cleared for public binary/container release. GHCR publishing requires repository variables `ALLOW_PUBLIC_RELEASE=true`, `LICENSE_REVIEW_PASSED=true`, and `LIVE_VALIDATION_PASSED=true`; leave them unset until the checks above and technical readiness requirements pass. The GHCR job publishes a tagged Linux/amd64 image with BuildKit SBOM/provenance attestations after CI passes. GHCR package visibility must still be set to Public by repository administrators if public distribution is intended.

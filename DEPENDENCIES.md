# Dependency and provenance inventory

Versions below are pinned by upstream module metadata or a release tag. The wireproxy release archive is verified in `Dockerfile` with SHA-256 `aa05dbc67198b56417334e4aa8bfca73cd23ba946eb70e1c7205b2319d618311`.

| Component | Version/commit | License | Copyright/provenance | Usage | Obligations | Audit status |
|---|---|---|---|---|---|---|
| AWG Switcher | this source tree | MIT | AWG Switcher contributors | Original controller/proxy | Retain MIT notice | Text added |
| bropines/awg-wireproxy | v2.1.0 / `02588433b6328171b594d76f3f16bd3404258a83` | ISC | Tsz Fung Wong; bropines; fork provenance includes windtf/wireproxy and artem-russkikh/wireproxy-awg | Separate executable in runtime image | Retain copyright and permission notice | Tag license checked; unsigned annotated tag |
| amneziawg-go | v3.1.20260828 / `b5928efb6ca19f0153958460c3d141f04abc5c2e` | MIT | WireGuard LLC and contributors; WireGuard-Go fork | Statically included in wireproxy binary | Retain MIT notice | Module/version and license checked |
| yaml.v3 (`go-yaml/yaml`) | v3.0.1 | MIT AND Apache-2.0 (file-specific dual licensing) | Kirill Simonov; Canonical Ltd; libyaml-derived files | Direct Go module in controller | Preserve relevant MIT/Apache text and notices | Checked; full dual-license text and upstream `NOTICE` included |
| MakeNowJust/heredoc/v2 | v2.0.1 | MIT | Upstream contributors; notice in bundled license file | wireproxy dependency | Retain MIT notice | `go-licenses` Linux/amd64 inventory |
| akamensky/argparse | v1.4.0 | MIT | Upstream contributors; notice in bundled license file | wireproxy dependency | Retain MIT notice | `go-licenses` Linux/amd64 inventory |
| go-ini/ini | v1.67.0 | Apache-2.0 | Upstream contributors; notice in bundled license file | wireproxy dependency | Preserve license and any upstream NOTICE (none found in module checkout) | `go-licenses` Linux/amd64 inventory |
| google/btree | v1.1.3 | Apache-2.0 | Google and contributors; bundled license | wireproxy dependency | Preserve license and any upstream NOTICE (none found in module checkout) | `go-licenses` Linux/amd64 inventory |
| go-landlock | v0.10.1 | MIT | go-landlock contributors | wireproxy dependency | Retain MIT notice | `go-licenses` Linux/amd64 inventory |
| things-go/go-socks5 | v0.1.3 | MIT | things-go contributors | wireproxy dependency | Retain MIT notice | `go-licenses` Linux/amd64 inventory |
| golang.org/x/crypto | v0.57.0 | BSD-3-Clause | The Go Authors and contributors | wireproxy dependency | Retain copyright, conditions and disclaimer | `go-licenses` Linux/amd64 inventory |
| golang.org/x/exp | v0.0.0-20250711185948-6ae5c78190dc | BSD-3-Clause | The Go Authors and contributors | wireproxy dependency | Retain copyright, conditions and disclaimer | `go-licenses` Linux/amd64 inventory |
| golang.org/x/net | v0.59.0 | BSD-3-Clause | The Go Authors and contributors | wireproxy dependency | Retain copyright, conditions and disclaimer | `go-licenses` Linux/amd64 inventory |
| golang.org/x/sys | v0.48.0 | BSD-3-Clause | The Go Authors and contributors | wireproxy dependency | Retain copyright, conditions and disclaimer | `go-licenses` Linux/amd64 inventory |
| golang.org/x/time | v0.15.0 | BSD-3-Clause | The Go Authors and contributors | wireproxy dependency | Retain copyright, conditions and disclaimer | `go-licenses` Linux/amd64 inventory |
| gvisor.dev/gvisor | v0.0.0-20261009044828-bd481cb16efb | Apache-2.0 | Google and contributors; bundled license | wireproxy dependency | Preserve license and any upstream NOTICE (none found at module root) | `go-licenses` Linux/amd64 inventory |
| suah.dev/protect | v1.2.4 | ISC | qbit contributors | wireproxy dependency | Retain ISC notices | `go-licenses` Linux/amd64 inventory |
| kernel.org/libcap/psx | v1.2.77 | BSD-3-Clause OR GPL-2.0-only | libcap/psx contributors | Linux Landlock syscall support in wireproxy dependency tree | Select BSD-3-Clause option; retain complete dual-license text and BSD notices. GPL option is not selected. | Manually inspected SPDX `BSD-3-Clause OR GPL-2.0-only`; do not treat automated GPL-only classification as the full license expression |
| Go standard library/runtime | Go 1.27.1 | BSD-3-Clause | The Go Authors | Compiled into both Go executables | Reproduce Go copyright, conditions and disclaimer | Text included at `licenses/GO-LICENSE` |
| Alpine build stages | Alpine 3.22 and 3.23, amd64 OCI digests pinned in `Dockerfile` | Mixed (build-only) | Alpine contributors | Build tools and CA bundle source | Build stage not shipped; package notices still recorded | Digest-pinned references checked; Docker build not run |
| Mozilla-derived CA bundle | Alpine `ca-certificates-bundle=20261020-r0` from Alpine v3.22/x86_64 | `MPL-2.0 AND MIT` per Alpine APKINDEX/APKBUILD; individual CA certificate terms may also apply | Mozilla and individual certificate authorities; Alpine packaging copyright | Root trust data copied into runtime image | Preserve license texts/notices; do not modify the covered bundle | Version and license metadata checked; final image package/cert audit pending |

The upstream `wireproxy v2.1.0` tag is annotated but unsigned (`verification.verified=false`). The release binary embeds the exact tagged source revision, but a reproducible source-to-binary build was not completed. This remains a provenance risk. The project directory is not a Git checkout in the current environment, so secret scanning of commit history could not be run here; CI is configured to scan full history once published. The committed `sbom.cdx.json` covers the Go module dependency graph as generated on the development host, not the final container; CI is configured to emit a separate image SBOM.

The dependency license inventory was generated with `google/go-licenses v1.6.0` against the exact v2.1.0 source checkout. It reported only the listed permissive licenses; it emitted warnings that architecture-specific assembly files could not be inspected. Manual legal review is not provided by this software project and automated classification is not a legal opinion.

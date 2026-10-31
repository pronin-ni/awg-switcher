# Third-party notices

AWG Switcher is not an official AmneziaVPN product and is not affiliated with or endorsed by AmneziaVPN. Product and project names remain the property of their respective owners.

## Distributed runtime components

The Docker image includes the upstream `wireproxy` executable and the Go application. The image also includes the Mozilla-derived `ca-certificates-bundle=20261020-r0` root bundle from Alpine v3.22/x86_64 for outbound TLS verification. Alpine declares that package `MPL-2.0 AND MIT`; the MPL 2.0 text is in `licenses/mozilla-ca/MPL-2.0.txt`. CA certificates are issued by their respective authorities and may carry certificate-specific terms. The package version is pinned in the Docker build; exact package/certificate notice contents still need final image verification. License documents for Go dependencies are included under `/usr/share/licenses/` in the image and under `licenses/` in this source repository.

### wireproxy

`bropines/awg-wireproxy` v2.1.0, tag commit `02588433b6328171b594d76f3f16bd3404258a83`, ISC license. Copyright notices retained in `licenses/awg-wireproxy/github.com/bropines/awg-wireproxy/LICENSE`: Tsz Fung Wong (upstream windtf/wireproxy) and bropines (AmneziaWG and UDP proxy adaptations). This is a separately built upstream executable, not code represented as authored by AWG Switcher.

The release source traces to `windtf/wireproxy` and `artem-russkikh/wireproxy-awg`; the release's own license notice was checked and preserved. Its Go dependency licenses are provided under `licenses/awg-wireproxy/`.

### AWG cryptographic engine

The bundled wireproxy v2.1.0 reports dependency `github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828`, commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`, MIT license, copyright WireGuard LLC and contributors. Its license text is retained in `licenses/awg-wireproxy/github.com/amnezia-vpn/amneziawg-go/v3/LICENSE`.

### yaml.v3

`gopkg.in/yaml.v3 v3.0.1` (module `go-yaml/yaml`), MIT and Apache-2.0 dual-licensed. License text is retained in `licenses/yaml.v3/LICENSE`. `go-licenses` identifies MIT for the imported package; the full upstream dual-license text is preserved.

See `DEPENDENCIES.md` and `licenses/` for the detailed component inventory and required notices. The source license above applies only to original AWG Switcher code; it does not replace these third-party terms.

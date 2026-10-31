# AWG Switcher

AWG Switcher is a single-container HTTP forward proxy with independent WireGuard/AmneziaWG userspace sessions and HTTPS-based failover. It does not create a host tunnel, change host routes, or provide a DIRECT fallback. HTTP targets and target hostnames are sent through the active profile's loopback SOCKS5 listener.

> **Status: development / not production-ready.** Linux/amd64 Docker build and two-profile LIVE checks have run on a dedicated test VPS. The observed public egress-IP fingerprints for both supplied profiles were identical; the requested Radarr endpoints also did not complete CONNECT from that test network. See [`TESTING.md`](TESTING.md). Do not use this image for production, and do not publish a GHCR release until all gates pass.

## Components and limitations

- Controller and HTTP(S) proxy: Go; listen on port `20171` inside the container.
- Engine: pinned `bropines/awg-wireproxy v2.1.0`, embedding AmneziaWG Go `v3.1.20260828`.
- One supervised engine/SOCKS5 listener per discovered valid profile. Backoff is exponential and capped; process logs are discarded to avoid accidental key disclosure.
- Priority selection, HTTPS probes through each profile, failure/recovery thresholds, cooldown, primary recovery, and fail-closed behavior are implemented.
- WireGuard and AWG fields accepted by the pinned parser are preserved. Bare IPv4/IPv6 addresses are normalized to `/32` and `/128`. Unknown fields are rejected, not silently dropped. Parser acceptance alone does not establish compatibility with every AWG version; compatibility must be verified with the pinned engine.
- No proxy authentication is implemented. Attach only trusted clients to the proxy Docker network. Do not publish port `20171` to the internet.
- `health.urls` must be HTTPS. Any HTTP response (including 403, 429, or 5xx) proves the route reached that endpoint; a site-specific HTTP error is not treated as VPN failure.

Licensing remains **LICENSE REVIEW REQUIRED**. The pinned upstream wireproxy tag is unsigned; the release artifact is hash-pinned and its embedded source revision was checked, but source-to-binary reproducibility and a container-level license/SBOM audit remain open. See [`LICENSE_STATUS.md`](LICENSE_STATUS.md).

## TerraMaster / Portainer layout

Use one stack and the following host paths:

```text
/Volume2/docker/awg-switcher/
├── configs/
│   ├── primary.conf
│   ├── backup1.conf
│   └── backup2.conf
├── settings.yaml
└── data/
```

1. Create the directories and copy `settings.example.yaml` to `settings.yaml`.
2. Copy only the desired real profiles to `configs/`. Do not commit them. Protect the directory and backups as secrets.
3. Edit `profiles.primary` and `profiles.priority` to match the exact filenames.
4. The container runs as UID/GID `10001`. Make the mounted files readable only by that UID and the directory traversable by it (for example, `chown -R 10001:10001 configs settings.yaml data && chmod 0700 configs data && chmod 0400 settings.yaml configs/*.conf`). Keep the parent deployment directory protected from other host users.
5. Ensure the external Docker network `proxy-network` exists. The Compose stack does not create a NAS tunnel or modify global routes.
6. Deploy the repository's `docker-compose.yml` from `/Volume2/docker/awg-switcher/` (or use its equivalent Portainer stack with the same mounts and security settings). The current Compose file builds the image locally; a public GHCR image is not yet released.
7. Keep the service name `awg-switcher` and do not add a host port mapping. Consumers attached to `proxy-network` use `http://awg-switcher:20171`.

```sh
mkdir -p /Volume2/docker/awg-switcher/{configs,data}
cp settings.example.yaml /Volume2/docker/awg-switcher/settings.yaml
docker network inspect proxy-network >/dev/null 2>&1 || docker network create proxy-network
cd /Volume2/docker/awg-switcher
chown -R 10001:10001 configs settings.yaml data
chmod 0700 configs data
chmod 0400 settings.yaml configs/*.conf
docker compose config
docker compose up -d --build
docker compose logs -f awg-switcher
```

The image runs as UID/GID `10001`, with a read-only root filesystem and a private runtime tmpfs. Mount profile files read-only. `/healthz` reports process liveness; `/readyz` requires a healthy VPN profile. `/api/status`, `/api/profiles`, and `/api/active` expose status only on the attached Docker network. Do not attach untrusted containers to this network.

## Configure and verify

See [`settings.example.yaml`](settings.example.yaml). Defaults are 15-second checks, 8-second timeout, 2 failed checks to mark unavailable, 3 passing checks to recover, 60-second recovery-probe interval for higher-priority profiles, and 30-second switch cooldown. Emergency failover is not delayed by cooldown.

From an attached test container:

```sh
curl -x http://awg-switcher:20171 https://api.ipify.org
curl -x http://awg-switcher:20171 https://www.cloudflare.com/cdn-cgi/trace
curl http://awg-switcher:20171/api/status
```

To test failover, use an isolated test stack and interrupt only its selected engine/route. Confirm `/api/status` changes **and** send a new request through the proxy to check the actual egress path. Confirm the primary returns after the configured recovery threshold. Never test by changing NAS routes or stopping another service. With every profile down, proxy requests must fail with 502/503; they must never be sent directly.

## Update and rollback

Back up `settings.yaml` and `configs/` securely. Keep the previous tested source/image tag available. Rebuild/deploy the new revision without deleting the config mounts. To roll back, restore the previous Compose/source revision and settings, then recreate only the `awg-switcher` service. The current data mount is reserved and does not contain VPN keys.

## Development checks

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.2.0 ./...
docker compose config
docker build --platform linux/amd64 -t awg-switcher:test .
```

Real `.conf` files belong only in the local ignored `creds/` directory or the deployment's protected `configs/` directory; never add them to tests, build contexts, or CI.

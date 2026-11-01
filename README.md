# AWG Switcher

AWG Switcher is a single-container AmneziaWG/WireGuard proxy with a protected self-hosted management UI. The Go controller supervises independent `bropines/awg-wireproxy v2.1.0` sessions, routes HTTP(S) via per-profile SOCKS5, and fails closed when no VPN route is healthy. It does not configure host/NAS routes.

> **Development / not production-ready.** The UI/admin service, runtime profile manager and persistence are under active validation. Prior LIVE checks proved HTTPS via two real profiles and failover/recovery, but the profiles had identical public egress-IP fingerprints. Radarr endpoints did not complete from the prior test exits. Licensing/provenance review remains open. No GHCR stable image is published. See [TESTING](TESTING.md) and [LICENSE_STATUS](LICENSE_STATUS.md).

## Ports and security

- `20171`: forward proxy only. Never publish it to a host port or the internet. Use `http://awg-switcher:20171` from trusted containers on `proxy-network`.
- `8080`: Web UI and authenticated admin API. Not published by default in Compose. Bind it only to a trusted LAN address or reach it through an SSH tunnel. First-admin creation is local CLI only: `docker exec -it awg-switcher /usr/local/bin/awg-switcher create-admin`.
- Admin password uses Argon2id; session cookies are HttpOnly/SameSite Strict; mutating API requests require CSRF. The panel has no remote account registration. The proxy listener does not serve administrative APIs.

The app runs as UID/GID `10001`, with a read-only root filesystem, only `/run/awg-switcher` tmpfs and `/app/data` writable. Filesystem profiles remain read-only in `/app/configs`; UI-imported profiles are stored as `0600` files in `/app/data/profiles`. `state.db` is a compact JSON state document, written atomically with mode `0600`; it stores profile metadata and a bounded switch/error/restart event history (no database daemon or dependency). Private keys are never included in profile-list JSON or safe config view.

## TerraMaster / Portainer

Host layout:

```text
/Volume2/docker/awg-switcher/
├── configs/          # optional legacy/read-only .conf files
├── settings.yaml
└── data/             # admin hash, state.db, profiles/ (chmod 0600)
```

1. Create directories and settings; keep VPN configs private.
2. Ensure Docker network `proxy-network` exists.
3. Set volume ownership to UID/GID 10001; deploy `docker-compose.yml` as one stack. It publishes **no host ports**.
4. For the first admin, use `docker exec -it awg-switcher /usr/local/bin/awg-switcher create-admin`; enter a long unique password twice. Never put it in Compose, shell arguments, or logs.
5. To use the panel on the NAS LAN, add the optional `ports` section from [`docker-compose.lan.example.yml`](docker-compose.lan.example.yml), after verifying the NAS LAN address. It binds `192.168.31.12:2080` only; do not add a proxy host mapping. The UI is `http://192.168.31.12:2080`.
6. Import one or more `.conf` files in the UI, inspect status, then configure client containers to use `http://awg-switcher:20171`.

Example preparation (run as an administrator on the NAS):

```sh
mkdir -p /Volume2/docker/awg-switcher/{configs,data}
cp settings.example.yaml /Volume2/docker/awg-switcher/settings.yaml
chown -R 10001:10001 /Volume2/docker/awg-switcher/{configs,data}
chown 10001:10001 /Volume2/docker/awg-switcher/settings.yaml
chmod 0700 /Volume2/docker/awg-switcher/{configs,data}
chmod 0400 /Volume2/docker/awg-switcher/settings.yaml
docker network inspect proxy-network >/dev/null 2>&1 || docker network create proxy-network
```

The base Compose uses a local Docker build. No image is published yet. Keep Jellyfin video, NPM, qBittorrent and other production service routing unchanged unless separately approved.

## UI features

- Dashboard with active route, health, profile counts, switch count, uptime and in-flight proxy requests; polling refreshes the display. A bounded event history survives container restarts.
- Import `.conf` at up to 1 MiB each, multiple files, drag-and-drop, safe view, profile rename, priority, enable/disable, manual primary selection (30-minute maximum), health check and deletion of imported profiles.
- URL diagnostics accepts HTTPS only and probes through the selected profile's SOCKS5 route. DNS resolution for the target hostname is requested through SOCKS5; there is no direct fallback.
- English/Russian interface, responsive layout and light/dark system mode. Language/theme preferences are the only UI settings in localStorage; credentials and config secrets are not.

`/healthz` reports process liveness and `/readyz` is 200 only with an active healthy VPN. When there are no configs, the process and UI remain available while readiness and proxy requests fail closed.

## Verification and operations

```sh
docker compose config --quiet
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

Logs: `docker compose logs -f awg-switcher`. The panel shows profile state and persisted recent switch/engine events. Back up `settings.yaml`, `configs/` and the protected `data/` directory before upgrades. To roll back, restore the previous tested source/image and Compose/settings, then recreate only `awg-switcher`; do not delete `data/`.

The UI/admin implementation must be treated as development until its live Docker E2E, security review, VPS checks, and license/provenance review are completed. Do not expose admin through NPM/public internet by default.

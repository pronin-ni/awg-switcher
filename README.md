# AWG Switcher

AWG Switcher is a single-container AmneziaWG/WireGuard proxy with a protected self-hosted management UI. The Go controller supervises independent `bropines/awg-wireproxy v2.1.0` sessions, routes HTTP(S) via per-profile SOCKS5, and fails closed when no VPN route is healthy. It does not configure host/NAS routes.

> **Development image.** Pushes to `main` publish `ghcr.io/pronin-ni/awg-switcher:dev` after CI succeeds. `latest` is reserved for an explicitly validated stable release. A previous VPS test confirmed two real profiles, failover and recovery; Radarr destinations did not work through the tested VPN exits. See [TESTING](TESTING.md).

## Ports and security

- `20171`: forward proxy only. Never publish it to a host port or the internet. Use `http://awg-switcher:20171` from trusted containers on `proxy-network`.
- `8080`: Web UI and authenticated admin API. The Portainer example binds it to the NAS LAN address at port `2080`; change that address to match your NAS. Do not expose it to the public internet.
- Admin password uses Argon2id; session cookies are HttpOnly/SameSite Strict; mutating API requests require CSRF. The panel has no remote account registration. The proxy listener does not serve administrative APIs.

The container initializes `/app/data` ownership on first start, then drops to UID/GID `10001`. It has a read-only root filesystem, `/run/awg-switcher` tmpfs, and only the persistent data mount writable. UI-imported profiles are stored as `0600` files in `/app/data/profiles`. The state file stores profile metadata and a bounded switch/error/restart event history. Private keys are never included in profile-list JSON or safe config view.

## TerraMaster / Portainer

Create the external Docker network once if it does not already exist. In Portainer, create a Stack and paste this Compose (adjust the NAS IP/path if needed):

```yaml
services:
  awg-switcher:
    image: ghcr.io/pronin-ni/awg-switcher:dev
    container_name: awg-switcher
    restart: unless-stopped
    ports:
      - "192.168.31.12:2080:8080"
    volumes:
      - /Volume2/docker/awg-switcher:/app/data
    networks:
      - proxy-network
networks:
  proxy-network:
    external: true
```

1. Create the Stack and deploy. The app initializes the empty persistent folder itself; no settings file or config folders are needed.
2. Open the container logs in Portainer, copy the one-time setup code, then open `http://192.168.31.12:2080` and create the administrator. The setup code is invalidated after use.
3. Upload AWG `.conf` files through the UI. The first uploaded profile becomes primary; later profiles join the automatic failover pool.
4. Point trusted containers attached to `proxy-network` at `http://awg-switcher:20171`. The proxy port is not published on the NAS host. When stable release validation is complete, change the image tag from `dev` to `latest`.

For Docker-only development from a checkout, use `docker-compose.dev.yml`; the Portainer stack above pulls the published development image.

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

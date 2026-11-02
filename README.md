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
    read_only: true
    tmpfs:
      - /run/awg-switcher:rw,noexec,nosuid,size=16m,uid=10001,gid=10001
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - FOWNER
      - SETGID
      - SETUID
    security_opt:
      - no-new-privileges:true
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

### TerraMaster TOS 6: diagnose first-start permission failures

No manual ownership or mode changes should be needed. If Portainer logs report `initialize data directory ownership` or `secure data directory`, collect the exact error and inspect the bind mount on TOS over SSH:

```sh
stat -c 'mode=%a owner=%u:%g path=%n' /Volume2/docker/awg-switcher
findmnt -T /Volume2/docker/awg-switcher -o TARGET,FSTYPE,OPTIONS
getfacl -cp /Volume2/docker/awg-switcher
```

If `getfacl`/`findmnt` is unavailable, inspect that folder in **TOS Control Panel → Privilege → Shared Folder → Access Control** and confirm the Docker service can write there. A filesystem/ACL diagnostic can test the exact container capabilities on a disposable child directory (this is diagnostics only; do not run on the application data files):

```sh
docker run --rm --cap-drop=ALL --cap-add=CHOWN --cap-add=FOWNER \
  --cap-add=SETGID --cap-add=SETUID --security-opt no-new-privileges:true \
  -v /Volume2/docker/awg-switcher:/data alpine:3.22 sh -ec '
    d=/data/.awg-permission-check; trap "rm -rf \"$d\"" EXIT
    mkdir "$d" && chown 10001:10001 "$d" && chmod 700 "$d"
    stat -c "mode=%a owner=%u:%g path=%n" "$d"
  '
```

If this probe reports `Operation not permitted`, the shared-folder ACL or filesystem does not allow ownership changes despite the container capability. Keep the data directory on a local TOS filesystem that supports Unix ownership and grant the Docker-managed folder write access using TOS ACL controls; do not switch to privileged mode or weaken container capabilities.

For Docker-only development from a checkout, use `docker-compose.dev.yml`; the Portainer stack above pulls the published development image.

## UI features

- Dashboard with active route, health, profile counts, switch count, uptime and in-flight proxy requests; polling refreshes the display. A bounded event history survives container restarts.
- Import `.conf` at up to 1 MiB each, multiple files, drag-and-drop, safe view, profile rename, priority, enable/disable, manual primary selection (30-minute maximum), health check and deletion of imported profiles.
- URL diagnostics accepts HTTPS only and probes the selected profile without changing global failover. Network Debug is opt-in for 10 minutes; the bounded JSON support report excludes profile errors, URL paths/queries, credentials, and engine output. “Full connection check” probes ipify, Facebook, and Radarr sequentially through that same profile.
- Every enabled, running profile (active and standby) receives HTTPS checks through its own SOCKS5 engine every `failover.check_interval` (default 15s); checks share the configured overall timeout (default 8s). Connectivity health is distinct from service health: any valid HTTP response, including 403/429/5xx, proves the HTTPS route works; at least one 2xx/3xx endpoint is needed for the service-health signal. A single endpoint outage therefore cannot cause VPN failover.
- The separate **Website checks** page lets an administrator select public HTTPS sites, expected statuses, required-site or minimum-success policy, timeout/failure/recovery thresholds, and interval, daily, or five-field cron scheduling with an IANA time zone. Its scheduler is independent of the 15-second VPN health monitor. Policy settings are previewed and require explicit confirmation; a confirmed Website FAIL blocks new routing through that profile, triggers immediate failover, and recovery uses the configured success threshold. Restart always resets Website routing eligibility to `PENDING` until a fresh website check. Manual profile pinning is retained while a blocked target uses an eligible backup.
- Website checks always use the target profile's SOCKS5 engine, verify TLS certificates, follow only safe HTTPS redirects, pin public DNS answers for each request, reject private/reserved destinations, and never use DIRECT. Only expected HTTP statuses pass. Results/history (seven days, bounded) and settings are stored with restrictive permissions in `/app/data`; URL query strings are removed from history. The preset Rutracker/Facebook/Radarr/GitHub URLs are opt-in templates and are not automatically enabled.
- Website-policy configuration changes show a per-profile forecast before confirmation; schedules alone can be changed without triggering extra site checks. A site failing through every VPN is surfaced as a possible site-side outage. Imports and generated profiles are checked by Website Monitor before they can enter a policy-controlled routing pool; automatic generation remains disabled.
- Failover requires consecutive failures; recovery requires consecutive successes plus a stable recovery window before returning to a higher-priority route. Passive transport errors from actual proxy traffic only trigger independent HTTPS confirmation and never directly switch routes. Switch events include the confirmed cause. The proxy remains fail-closed, with no DIRECT fallback.
- Health samples and switch events are saved in the protected `state.db` volume and survive container restart. Per-profile 24-hour and 7-day connectivity/service success rates are shown in Profiles. `health.minimum_healthy_profiles` defaults to 2 and displays a prompt to add another profile below that count; generation is always user-confirmed and newly generated profiles must pass an engine check.
- Several WARP profiles may share Cloudflare infrastructure; they are not independent protection against provider-wide blocking. Use profiles from genuinely different providers/failure domains for resilient failover.
- Manual diagnostics default to 30 seconds, proxy CONNECT to 30 seconds, TLS handshake to 10 seconds, and HTTP response headers to 20 seconds. DNS resolution is delegated to wireproxy and reported as unobservable at the application boundary; diagnostics do not mutate health state or global selection.
- English/Russian interface, responsive layout and light/dark system mode. Language/theme preferences are the only UI settings in localStorage; credentials and config secrets are not.

### WARP config generator

In **Profiles**, use **＋ Сгенерировать WARP** beside **＋ Добавить профиль**. The standard mode calls the public `https://awgconfig.com` API from the AWG Switcher backend; no additional container, YAML or environment variables are needed. Choose AWG 2.0/3.0/3.1 and 1–3 profiles. Requests use hostname Endpoint, IPv4 full tunnel (`AllowedIPs = 0.0.0.0/0`) and stable CPS; Endpoint Lab and experimental CPS options are not enabled.

The backend decodes and validates each returned config, stores it locally with restrictive permissions, and checks HTTPS (`https://api.ipify.org`) through a temporary AWG engine on the AWG Switcher host. A profile that passes is enabled at the end of the profile priority list as a backup; a failed profile remains disabled and its reason is shown in the dialog. An existing healthy primary profile is not replaced. On an empty install, a verified generated profile can become the first available route. Private keys stay on the backend and are not returned to the browser or written to application logs.

Self-hosting is optional: open **Additional settings · self-hosted generator** in the dialog and set an HTTPS URL (with Bearer authentication if required). For a local Docker service, `generator/docker-compose.yml` builds upstream `amnezia-config-gen` at pinned commit `cebc09e46f636f74e6ddc4ec1dae94b8d3046e12`; no upstream source is copied into AWG Switcher and that Compose publishes no host port. The backend rejects arbitrary HTTP/private remote destinations and does not follow redirects.

`/healthz` reports process liveness and `/readyz` is 200 only with an active healthy VPN. When there are no configs, the process and UI remain available while readiness and proxy requests fail closed.

## Verification and operations

```sh
docker compose config --quiet
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

`bun tests/browser-smoke.mjs` checks the first-run UI and the visible generator action/modal. `bun tests/browser-warp-e2e.mjs` is a manual live test that creates one real WARP registration at awgconfig.com, then validates/imports/probes it through the real engine in a temporary container. It only prints a pass/fail summary; run it only when a test registration is acceptable.

Logs: `docker compose logs -f awg-switcher`. The panel shows profile state and persisted recent switch/engine events. Back up the persistent `/app/data` directory before upgrades. To roll back, restore the previous tested image and Compose, then recreate only `awg-switcher`; do not delete the data directory.

The UI/admin implementation must be treated as development until its live Docker E2E, security review, VPS checks, and license/provenance review are completed. Do not expose admin through NPM/public internet by default.

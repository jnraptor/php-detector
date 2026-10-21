# php-detector

Finds **every PHP process on this server** and tells you whether it runs on the
host or inside a container — and if it is in a container, exactly which one.

```
./php-detector.sh
```

```
PHP PROCESS INVENTORY  myserver.example.com  2026-10-21 22:41:41

LOCATION                   ENGINE   IMAGE / SYSTEMD UNIT               PHP          PROCS  PIDS
host:php8.3-fpm.service    host     php8.3-fpm.service                 8.3.6            3  4085775 4085776 4085777
docker:speedtest           docker   henrywhitaker3/speedtest-tracker   7.4.15           4  3906733 3906734 3906759 3906760

PID      USER       ROLE        PHP          LOCATION                 COMMAND
3906733  root       fpm-master  7.4.15       docker:speedtest         php-fpm: master process (/etc/php7/php-fpm.conf)
3906734  jon        cli         7.4.15       docker:speedtest         php /config/www/artisan queue:work --timeout=120
4085775  root       fpm-master  8.3.6        host                     php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)

RESTART COMMANDS
  host:php8.3-fpm.service    systemctl restart php8.3-fpm.service
  docker:speedtest           docker restart 75ecfbf902ba5756baea3bb90bce27cf8bc23ec6170d2e95ab37ddddf53e7f63
```

## Options

| Option | Meaning |
|---|---|
| `-s, --summary` | only the per-location summary table |
| `-v, --versions` | probe PHP versions (default) |
| `--no-versions` | skip version probing — fastest, no `docker exec` |
| `-m, --min-version V` | flag every PHP older than `V` as `OUTDATED` |
| `-p, --packages` | also list installed host PHP packages (dpkg) |
| `-j, --json` | machine readable output |
| `-w, --watch [SEC]` | re-run the scan every `SEC` seconds |
| `-h, --help` | help |

```bash
./php-detector.sh -m 8.3.10          # what is still on an old PHP?
./php-detector.sh --json | jq .      # feed into other tooling
sudo ./php-detector.sh                # root also sees other users' processes
```

## How container vs. host is decided

`ps aux` cannot tell you this — inside a container the process looks exactly
like a host process. The script therefore reads `/proc` directly:

| Source | Signal | Meaning |
|---|---|---|
| `/proc/<pid>/cgroup` | `docker-<id>.scope`, `/docker/<id>`, `cri-containerd-<id>.scope`, `libpod-<id>.scope` | container id → exact container, **works without root** |
| `/proc/<pid>/status` | `NSpid:` with more than one value | process is inside a PID namespace, i.e. containerised |
| `/proc/<pid>/ns/pid` | namespace inode compared with every container's init process | exact container match (needs root for other users' processes) |
| `/proc/<pid>/cgroup` | `php8.3-fpm.service` | the systemd unit, so the restart command is exact |

Fallback chain per process: **cgroup id → pid-namespace match → PID-namespace
flag (reported as `container:unknown`) → host**.

## PHP version detection

Per location (not per process — a location always runs one PHP build):

* **host** — runs the binary in `/proc/<pid>/exe`; if that is not readable
  (non-root), it derives the series from the config path
  (`/etc/php/8.3/fpm/php-fpm.conf` → `8.3`) and then uses `dpkg-query` on
  `php8.3-fpm` / `php8.3-cli`.
* **container** — `docker exec <id> <binary> -v`; falls back to well known
  paths (`/usr/local/bin/php`, `/usr/bin/php8.3`, …), then `php -v` in a shell,
  then running the binary through `/proc/<pid>/root` (works for containers that
  `docker exec` cannot reach).

## Notes

* Runs fine as a normal user; `sudo` only adds visibility of processes owned
  by other users and makes the `/proc/<pid>/exe` and `ns/pid` reads work.
* The `docker`/`podman` clients are optional — without them the cgroup id is
  still detected, the container is just shown by id.
* Works on cgroup v1 and v2, and covers `docker`, `podman`, `containerd`
  (incl. Kubernetes CRI) container ids.
* Version probing runs `php -v` inside each container, so a very short-lived
  `php -v` process may show up in a concurrent scan; zombie/exiting processes
  are filtered out.

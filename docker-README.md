# Is this you? — DNS hosting

Account-less hidden primary for DNSSEC-signed zones. A zone is accepted only when it validates, the parent DS matches a KSK in the zone, the parent NS set equals the apex NS set, and that set includes every nameserver of this deployment. The service never holds zone-signing keys.

NSD is the only public DNS server. Four supervised processes share `/opt/data`: the upload API, a zone-master controller, a UDP SOA/NOTIFY service, and a pre-fork TCP AXFR service. NSD transfers one RFC 9432 catalog zone from the local AXFR service and learns member zones only from that catalog.

The image is Alpine 3.24. The root filesystem is read-only. The repository is MIT licensed.

Full documentation: <https://github.com/IsThisYou-org/is-this-you-dns-host>

## Image

`jamesstevens/is-this-you-dns-host`

## Quick start

Persistent state is the `/opt/data` volume. Operator configuration is `/opt/data/etc/config.yaml`. If that file is absent at start, the image copies its bundled example into place. The process refuses to start until `service_ns` is set.

`/run` and `/tmp` are symlinks to `/dev/shm`. Compose sets `shm_size: 64mb`. There are no other tmpfs mounts.

From a checkout, Compose bind-mounts the example config read-only and publishes DNS and HTTP:

```sh
docker compose up --build
```

The same shape as a `docker run`. `--shm-size=64m` is the size CI uses for that tmpfs. `NET_BIND_SERVICE` lets NSD bind port 53 and nginx bind port 80. The container starts as root; NSD then drops to the `nsd` user and nginx workers run as `nginx`.

```sh
docker run -d --name dns-host \
  --read-only \
  --shm-size=64m \
  --cap-add NET_BIND_SERVICE \
  -p 53:53/udp -p 53:53/tcp -p 80:80 \
  -v dns-host-data:/opt/data \
  -v ./config.yaml:/opt/data/etc/config.yaml:ro \
  jamesstevens/is-this-you-dns-host
```

`docker compose up` does not publish TLS. The service speaks plain HTTP only. Put a reverse proxy in front for HTTPS. `docker-compose.tls.yml` adds `jamesstevens/easy-nginx` (MIT, <https://github.com/james-stevens/easy-nginx>) as that proxy. Use `deploy/config.tls.yaml` so `trusted_proxies` is the terminator's compose network (`172.28.9.0/24` in that file). Port 80 on the terminator redirects to HTTPS.

```sh
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

Place one PEM, certificate and private key together, at `deploy/easy-nginx/pems/upload.pem`, and set the public name in `deploy/easy-nginx/etc/nginx.input`.

## Ports

| Port | Bind | Role | Published by Compose |
| --- | --- | --- | --- |
| 53/udp, 53/tcp | `0.0.0.0` | NSD, the public DNS server | yes |
| 80/tcp | `0.0.0.0` | nginx: `GET /health`, `GET /config`, `POST /api/v1/zones/{apex}` | yes |
| 9100/tcp | `0.0.0.0` | `GET /metrics` only. Not published by Compose. Do not publish it on a public interface. | no |
| 5353/udp, 5353/tcp | `127.0.0.1` | Internal SOA, NOTIFY, and AXFR. Not published. | no |
| 8081/tcp | `127.0.0.1` | Internal nginx. Not published. | no |
| 8000/tcp | `127.0.0.1` | gunicorn. Not published. | no |

The image `HEALTHCHECK` runs every 30 seconds with a 3 second timeout. It passes only when nginx answers `GET http://127.0.0.1/health` and NSD returns the catalog SOA on `127.0.0.1:53`.

Publish port 9100 only on the network where Prometheus runs. The service does not authenticate `/metrics`.

## Configuration

`/opt/data/etc/config.yaml` is the configuration. Unknown keys are rejected. A repeated key is a warning: both line numbers are logged and the later value wins. The YAML file is not filled in from the environment.

`service_ns` must be set or the process will not start. Every name in that list must appear in the uploaded apex NS and in the parent delegation.

| Key | Default | Role |
| --- | --- | --- |
| `service_ns` | unset; start is refused | Public nameservers for this deployment. |
| `secondaries` | empty | Address, optional port (default 53), optional TSIG. NSD `notify` and `provide-xfr` come from this list. |
| `axfr_allow` | empty | Extra CIDRs allowed to AXFR, for debugging. A bare address is a /32 or /128. Not NOTIFY targets. |
| `allow-domains` | empty | Domains that may be uploaded. Empty allows every domain. Otherwise only a strict child of a listed name is accepted. The listed name itself is refused. |
| `resolver_base_url` | `https://api.isthisyou.org/` | JSON DoH API (`Accept: application/dns-json`). Not a binary DoH endpoint. |
| `catalog_zone` | `catalog.example.net.` | Catalog zone apex (RFC 9432). |
| `trusted_proxies` | empty | CIDRs allowed to send `X-Forwarded-For` and `X-Forwarded-Proto` on the external listener. |
| `grace_days` | `90` | How long to keep serving after RRSIG expiry or parent DS/NS drift. |
| `log_level` | `info` | Syslog severity (`debug`, `info`, `notice`, `warning`, `err`, `crit`, `alert`, `emerg`; `warn` and `error` are accepted). Production typically uses `warning`. |

Port 80, NSD (`0.0.0.0:53`), `/opt/data`, and the ICANN trust-anchor file (`/app/deploy/root-anchors.ds`) are fixed by the image. They are not configuration keys.

`allow-domains` matches whole labels after lower-casing and stripping a trailing dot. `isthisyou.me` allows `james.isthisyou.me` and `a.b.isthisyou.me`, and refuses `isthisyou.me` and `notisthisyou.me`. The check runs before any other validation, database work, or DNS lookup. A missing or empty list allows every domain.

Admission uses HTTPS to `resolver_base_url`. The container does not send its own DNS queries for lookups. If `secondaries` is set, NSD sends NOTIFY by UDP to each configured address. A TLD the ICANN root answers NXDOMAIN for is read from the resolver's local Handshake data. There is no Handshake trust-anchor setting.

`GET /config` is unauthenticated. It returns `{"ns": [...]}` from `service_ns`, in that order, with `Cache-Control: public, max-age=300`.

## Environment

| Variable | Effect |
| --- | --- |
| `GUNICORN_WORKERS` | Overrides `gunicorn_workers` (default 3). |
| `SYSLOG_STDOUT` | Set to `Y` to write syslog to the container's stdout, for testing. The file is not written. |
| `SYSLOG_SERVER` | `<host[:port]>`. Forward syslog to a remote server. Port 514 when omitted. Checked before `SYSLOG_STDOUT`. The file is not written. |

Otherwise logs go to `/opt/data/log/messages`. syslogd listens on the `/dev/log` socket and does not accept incoming network syslog.

## Further reading

Upload body, parent checks, key rollovers, and the on-disk layout are in the repository README:

<https://github.com/IsThisYou-org/is-this-you-dns-host>

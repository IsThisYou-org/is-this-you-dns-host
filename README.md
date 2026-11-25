# Is this you? — DNS hosting service

Account-less hidden primary for DNSSEC-signed zones. Anyone may upload a zone. It is accepted only when the zone validates, the parent DS matches a KSK in the zone, the parent NS set equals the apex NS set, and that set includes every nameserver of this deployment. The service never holds zone-signing keys.

NSD is the only public DNS server. Internally, four supervised processes share `/opt/data`: the upload API, a zone-master controller, a UDP SOA/NOTIFY service, and a pre-fork TCP AXFR service. NSD transfers a single RFC 9432 catalog zone from the local AXFR service and learns member zones only from that catalog. `nsd.conf` lists the catalog zone and the member pattern. It is not rewritten when a zone is added.

This repository is MIT licensed.

## Run it

The image is Alpine 3.24. Compose sets `read_only: true`. Persistent data is the `/opt/data` volume. `/run` and `/tmp` are symlinks to `/dev/shm`, and `shm_size` sizes that tmpfs. There are no other tmpfs mounts. Copy the example config if you want different nameservers; Compose bind-mounts it at `/opt/data/etc/config.yaml`.

```sh
docker compose up --build
```

`docker compose up` does not publish TLS. Put a reverse proxy in front if you want HTTPS. `docker-compose.tls.yml` adds the owner's [easy-nginx](https://github.com/james-stevens/easy-nginx) image (`jamesstevens/easy-nginx`, MIT) as that proxy. Use `deploy/config.tls.yaml` so `trusted_proxies` is the compose network of the terminator:

```sh
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

Place a PEM containing both the certificate and the private key at `deploy/easy-nginx/pems/upload.pem`, and set the public name in `deploy/easy-nginx/etc/nginx.input`. Port 80 on the terminator redirects to HTTPS. The service itself speaks plain HTTP only.

### Ports

| Port | Bind | Process | Published |
| --- | --- | --- | --- |
| 53/udp, 53/tcp | `0.0.0.0` | NSD, the public relay. Fixed address. | yes |
| 80/tcp | `0.0.0.0` | nginx external listener (`/api/` is the `/ext/` tree). Fixed address. | yes |
| 5353/udp | `127.0.0.1` | UDP service: SOA answers and NOTIFY. Fixed address. Not published. | no |
| 5353/tcp | `127.0.0.1` | Pre-fork AXFR service (default 5 children). Fixed address. IXFR is not requested. Localhost AXFR is always allowed. | no |
| 8081/tcp | `127.0.0.1` | nginx internal listener (`/api/` is the `/int/` tree). Fixed address. Not published. | no |
| 8000/tcp | `127.0.0.1` | gunicorn. Fixed address. Not published. | no |
| 9100/tcp | `0.0.0.0` | nginx metrics listener (`GET /metrics` only). Fixed port. Not published by Compose. | no |

Syslog is local. busybox `syslogd` listens on the `/dev/log` socket and writes `/opt/data/log/messages`. It is not a network service; a networked syslog would use port 514.

NSD binds port 53 as root and then drops to the `nsd` user. nginx's master binds port 80 as root; workers run as `nginx`. Compose adds `NET_BIND_SERVICE` and starts the container as root so those binds succeed on a read-only root. After the drop, NSD writes zone state under `/opt/data/nsd` and its pid under `/run/nsd`. nginx writes its generated config to `/run/nginx/nginx.conf` (rewritten at every start) and its temp files under `/tmp`. Gunicorn's control socket is `/run/gunicorn.ctl` (`--control-socket`; gunicorn 25.2 would otherwise create `$HOME/.gunicorn/gunicorn.ctl`). `PYTHONDONTWRITEBYTECODE=1`. Pid files, sockets and temp paths are under `/run` or `/tmp`, which are `/dev/shm`.

### Layout

| Path | Contents |
| --- | --- |
| `/opt/data/etc/config.yaml` | Operator configuration. A missing file is empty configuration. |
| `/opt/data/spool` | Validated zone documents, one uniquely named job per upload. `tmp/` holds the file before `rename`. Not sharded. |
| `/opt/data/zones` | The zone body, one JSON file under `<hh>/<ll>/`. `catalogue.json` stays in this directory. |
| `/opt/data/catalog` | Catalog file (zone names and full SOA records) and its mtime, which is the catalog SOA serial. One catalog, not sharded. |
| `/opt/data/nsd` | Generated `nsd.conf`, TSIG control keys, transfer state. NSD's zone copies are `zones/<c1>/<c2>/<name>.zone`. |
| `/opt/data/log` | Syslog output |
| `/opt/data/host.db` | Zone metadata, admission, grace, and counters. The zone body is the JSON file, not a row in this database. |
| `/run`, `/tmp` | Symlinks to `/dev/shm`: pid files, the gunicorn control socket, the generated nginx config (`/run/nginx/nginx.conf`), nginx temp files. NSD remote-control is TCP `127.0.0.1:8952`, not a socket here. |

### Per-zone files

The hidden primary stores each zone under two directory levels. The canonical zone name is the apex with surrounding whitespace removed, lowercased with `str.lower()`, and with every trailing dot removed. `james.isthisyou.me.` and `James.IsThisYou.Me` are both `james.isthisyou.me`. Stored apexes are already ASCII (IDNA); this step does not punycode them again.

The hash input is the UTF-8 bytes of that string. The digest is 32-bit FNV-1a: offset basis `2166136261` (`0x811c9dc5`), prime `16777619` (`0x01000193`), and for each byte `hash = (hash XOR byte) * prime` modulo `2**32`. The 32-bit value is xor-folded to 16 bits: the high 16 bits XOR the low 16 bits, `(hash >> 16) ^ (hash & 0xFFFF)`. `hh` is the high byte of that 16-bit value and `ll` is the low byte, each written as two lowercase hex digits. The path is `<dir>/<hh>/<ll>/<file>`. Two levels is the whole layout. It stays two levels as the number of zones grows.

For `james.isthisyou.me` the FNV-1a 32-bit hash is `0x9d00b292`, the folded value is `0x2f92`, and the relative directory is `2f/92/`.

| Store | Path for `james.isthisyou.me` |
| --- | --- |
| Zone document | `/opt/data/zones/2f/92/james.isthisyou.me.json` |
| NSD member zonefile | `/opt/data/nsd/zones/j/a/james.isthisyou.me.zone` |
| NSD catalog zonefile | `/opt/data/nsd/zones/catalog.zone` |

The hidden primary's files use the hash above. NSD cannot put a hash in a `zonefile` pattern, so member zones use NSD's own character substitutions: `zonefile: "%1/%2/%s.zone"` on the `catalog-member` pattern. `%1` and `%2` are the first and second characters of the zone name, and `%s` is the whole name. For `james.isthisyou.me` that is `j/a/james.isthisyou.me.zone`.

NSD's `get_char` (`options.c`) uses `.` when the requested character does not exist. A path component `.` is the current directory, so a one-character name `a` is written as `a/./a.zone`, which is `a/a.zone`. The same thing happens when the second character really is `.`, as in `a.example` (`a/./a.example.zone`). Those zones share the first-character directory. The file name is still the full zone name, so they do not overwrite each other.

NSD creates the missing parent directories itself. `namedb_write_zonefile` in `dbcreate.c` calls `create_dirs`, which `mkdir`s each component mode `0750` and treats "already exists" as success. The `nsd.conf` manual and `doc/UPGRADING` say the same: directories named in a `zonefile` path are created as needed. This service creates `/opt/data/nsd/zones` and gives it to the `nsd` user before NSD starts, so those `mkdir`s succeed after NSD drops privileges. The character directories are not pre-created.

`zonefiles-write: 60` stores a changed zone within 60 seconds. On restart NSD reads the file, then runs the normal SOA refresh against `127.0.0.1:5353` and AXFRs when that serial is newer.

Files left from the earlier hash layout, `/opt/data/nsd/zones/<hh>/<ll>/*.axfr`, are deleted at startup. NSD transfers each of those zones once and writes the character path. The hidden primary's files under `/opt/data/zones` stay in the hash layout. Flat files already in `/opt/data/zones` are moved into `<hh>/<ll>/` on startup. That move is safe to run again.

Directories for the hidden primary are created when a file is written. Writes stay under `/opt/data` (or on the `/run` and `/tmp` tmpfs).

The spool is a queue of uniquely named job files, one per upload, so it stays a single directory. Cron runs every 15 minutes. It deletes empty files older than five minutes at the top of `/opt/data/spool` (`find -maxdepth 1`) and files older than five minutes under `spool/tmp`. NSD's `xfrdir` holds transfer temps named `nsd-xfr-<pid>/xfr.<n>`. Those names are not zone names, so that directory is not sharded.

### HTTP

nginx presents each application tree as `/api/` on its own listener.

* External, port 80: `GET /health`, `GET /config`, `POST /api/v1/zones/{apex}`, and the same paths under `/ext/` on gunicorn. `/metrics` is not on this listener.
* Internal, `127.0.0.1:8081` (fixed): `POST /api/zones/drop` and `POST /api/zones/parent-state` (gunicorn paths `/int/zones/...`). Expire and delete are not on the public listener. gunicorn listens on `127.0.0.1:8000`, which is also fixed.
* Metrics, port 9100 (fixed): `GET /metrics`. nginx proxies that path to gunicorn `/int/metrics`.

`/health` reports the process, the catalog serial, and a localhost SOA query to the Python master. `/metrics` runs `nsd-control stats_noreset` and returns Prometheus text (`text/plain; version=0.0.4`). Names are prefixed `nsd_`. A failed scrape is HTTP 503 and `nsd_up 0`.

Publish port 9100 only on the internal network or the network where Prometheus runs. Do not publish it on a public interface. Restrict `/metrics` at the TLS shedder or the firewall as well if a scrape should not be anonymous; the service does not authenticate it.

`GET /config` is unauthenticated and is not under `/v1`. It returns `{"ns": ["ns1.example.net.", ...]}` from the configured `service_ns` list, in that order, and sets `Cache-Control: public, max-age=300`.

## Configuration

`/opt/data/etc/config.yaml` is the configuration. Environment variables are not read. A secondary's TSIG secret may be inline or in `tsig_secret_file` (a Docker secret mount is a normal place). Secrets are never taken from a zone upload. Port 80, NSD (`0.0.0.0:53`), the data directory (`/opt/data`), and the ICANN trust-anchor file (`/app/deploy/root-anchors.ds`) are fixed by the image. They are not configuration keys.

| Key | Default | Role |
| --- | --- | --- |
| `service_ns` | unset; the process refuses to start | Public nameservers. All of them must appear in the apex NS and in the parent delegation. |
| `secondaries` | empty | IP, optional port, optional TSIG. NSD `provide-xfr` and `notify` are generated from this list. |
| `axfr_allow` | empty | Extra CIDRs allowed to AXFR from NSD, for debugging. A bare address is a /32 or /128. `notify` is still generated only from `secondaries`. |
| `resolver_base_url` | `https://api.isthisyou.org/` | Base URL of a JSON DoH API (`Accept: application/dns-json`). Not a binary DoH endpoint (`application/dns-message`). |
| `catalog_zone` | `catalog.example.net.` | Catalog zone apex (RFC 9432). |
| `trusted_proxies` | empty | CIDRs allowed to supply `X-Forwarded-For` / `X-Forwarded-Proto` on the external listener. |
| `grace_days` | `90` | How long to keep serving after RRSIG expiry or parent DS/NS drift. |
| `max_body_bytes` / `max_rrsets` / `max_names` / `max_rdata_bytes` | 1 MiB / 2000 / 1000 / 4096 | Upload and rdata caps. |
| `log_level` | `info` | Minimum severity for application logs and the gunicorn error, access, and root loggers. |

`log_level` is a syslog severity name, matched without regard to case: `debug`, `info`, `notice`, `warning` (also `warn`), `err` (also `error`), `crit`, `alert`, `emerg`. Aliases are stored as the syslog name (`warn` becomes `warning`, `error` becomes `err`). The application `log()` drops anything less severe than this level, on stdout and on syslog. The same value sets the gunicorn `error`, `access`, and root loggers: `notice` is Python `INFO`, `err` is Python `ERROR`, and `crit`, `alert`, and `emerg` are Python `CRITICAL`. Production typically uses `warning`, which leaves routine per-request lines (a zone accepted or rejected, a rate limit, a NOTIFY that was sent) out of the log. An unrecognised value stops the process with a config validation error.

The example file lists the rate limits, the serial window, and the DS digest list. `handshake_root_servers` and `handshake_trust_anchor_file` together enable a second walk when the name is proved absent from the ICANN root.

Secondaries are one list. Each entry is an IP, an optional port, and an optional TSIG key name, secret (or `tsig_secret_file`), and algorithm. The generated NSD pattern emits `provide-xfr` and `notify` for those addresses. `axfr_allow` adds `provide-xfr` lines with `NOKEY` for each subnet, on the catalog zone and on the member pattern. Those subnets are not NOTIFY targets. A value that is not an IPv4 or IPv6 CIDR stops the process at startup.

## Try an upload

The phone builds and signs the zone. For a dry run on a workstation:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python3 -m dns_host.demo_zone \
  --apex user.example. \
  --service-ns ns1.example.net.,ns2.example.net. \
  > /tmp/zone.json
```

The command writes the upload JSON to stdout and the KSK DS to stderr. Before the first upload can succeed, the parent zone must already delegate to every `service_ns` name and publish that DS. A missing DS is the kill switch: new uploads fail, and the stored zone is dropped after `grace_days`.

```sh
curl -sS -X POST "http://127.0.0.1/api/v1/zones/user.example" \
  -H "content-type: application/json" \
  --data-binary @/tmp/zone.json
```

A success body is `{"apex", "serial", "catalogUpdated", "nextExpireHint"}`. `nextExpireHint` is the earliest RRSIG expiration. The first accept is HTTP 201; a later higher serial is HTTP 200.

The sample zone will not pass against the public resolver unless `user.example` is really delegated to this host. Point `resolver_base_url` at your own copy of the same JSON DoH API (`application/dns-json`, not a binary `application/dns-message` endpoint), or run the test suite, which signs a zone and answers the parent walk itself.

### Upload body

```json
{
  "kind": "dnsauth#signedZone",
  "apex": "user.example.",
  "rrsets": [
    {
      "kind": "dns#resourceRecordSet",
      "name": "user.example.",
      "type": "SOA",
      "ttl": 300,
      "rrdatas": ["ns1.example.net. hostmaster.user.example. 1731000000 3600 600 864000 300"]
    }
  ]
}
```

Names are stored absolute, lowercased, with one trailing dot. Unicode labels are converted with IDNA. A missing trailing dot is added; it does not make the name relative to the apex, so send `www.user.example.` and not `www`. Names inside rdata follow zone-file rules: no trailing dot means relative to the apex. Wildcards are rejected. Labels may contain underscore (`_auth`). Each `RRSIG` item is one covered type and uses that RRset's TTL; a rollover may include several signatures for the same covered type.

SOA serial is unix time. It must be greater than the serial already stored, not more than 5 minutes ahead of the service clock, and not older than one hour.

User zones are NSEC3 as in RFC 9276: iterations 0, empty salt, Opt-Out off. Plain NSEC zones are rejected. DNSKEY algorithm 13 or 15 (P-256 or Ed25519), with a flags-257 KSK. RRSIG lifetime is at most 30 days and the signature must be valid now. Current standard RR types plus WALLET (IANA type 262) are accepted when they validate. Obsolete, experimental, and private-use types (NULL, HINFO, MD, MF, MB, private-use numbers, and the like) are rejected before signature checks. `URI` and `WALLET` are accepted only at the zone apex. Each WALLET rdata is either two character-strings (type, identifier) or four (type, identifier, description, sort order). If the installed dnspython has no WALLET class, the same rdata is stored as RFC 3597 unknown-type wire.

### What the service checks, in order

Body size, then the per-IP upload rate, then JSON. After that, still offline: RRset, name, and rdata caps, owner names, one apex SOA, serial freshness, type policy, TTL bounds, DNSKEY, RRSIG metadata, the NSEC3 chain, apex NS contains every `service_ns`, and in-bailiwick NS names have A or AAAA glue. Glue is checked before any parent query because it does not need the parent.

Only then does the service spend a parent-lookup token. Failed parent results are cached per apex for `negative_cache_ttl_seconds` and a retry in that window does not query again. The walk uses the JSON DoH API (`application/dns-json`) and only these parameters: `name`, `type`, `do=1`, `rd`, `cd`, and `server` on `rd=0` queries. `rd=0` is only for data in the root zone: the root DNSKEY, the root NS, and the DS of a TLD (one label below the root). The ICANN root DNSKEY and NS are read from the resolver's local copy (`rd=0`, no `server`); the TLD DS is read with `rd=0` at the root nameservers. The Handshake fallback follows the same rule, sending `rd=0` for Handshake-root data to `handshake_root_servers`. TLD and lower DNSKEY, and DS below the TLD, use `rd=1` and `do=1` and do not send `server`. The signed NS of a zone below the root, used to continue the walk, is the same `rd=1` query. `do=1` answers are read from base64 `rdata`. Every RRset signature is validated locally. The resolver's AD bit is not trusted. `cd` follows `doh_cd`. A resolver transport failure is `parent_lookup_unavailable` (503) and the message includes the resolver error.

Delegation NS are not taken from that resolver. A recursive lookup for the child NS follows the referral into the child, and the child is not served until admission, so the resolver returns SERVFAIL. That failure is not a parent answer. For each zone cut on the walk, including the apex being admitted, the service asks the parent zone's authoritative nameservers directly over DNS: UDP port 53, and TCP to the same server when the UDP answer is truncated. The query has `rd=0`. Each parent nameserver is tried. Its addresses come from glue on an earlier response, or from the resolver as `rd=1` A and AAAA lookups with no `server`. The NS set is the referral in the AUTHORITY section, or the ANSWER section when the parent is also authoritative for the child. Those NS records are unsigned. The DS, still fetched through the resolver and validated against the parent DNSKEY, is what proves the chain. An authenticated NXDOMAIN or NODATA for the DS is unchanged.

If none of the parent nameservers can be reached, admission fails with `parent_lookup_unavailable` (503) and the message says the parent nameservers were unreachable, plus the detail (no address, timeout, and the like). If a parent answers NOERROR or NXDOMAIN and has no delegation NS, admission fails with `parent_chain_invalid` (403) and the message says the parent served no delegation for that name. A SERVFAIL or other non-answer from a nameserver that did respond is `parent_lookup_unavailable` as well, and the message names that rcode. It is not described as a missing delegation. Resolver queries and these direct queries share `max_doh_queries_per_walk` (a truncated UDP answer that is retried over TCP counts again).

The parent NS name set must equal the apex NS set. If the parent is missing a service NS the error is `parent_ns_incomplete` (403). Any other difference is `ns_set_mismatch` (422). The DS digest is compared to the uploaded KSK before any signature in the upload is verified. Signature verification is last.

On success the API writes the validated zone document into the spool (an empty `mktemp` file in `/opt/data/spool`, the JSON under `spool/tmp`, then `rename` over the empty file). The controller, not the API, installs that document as the sharded JSON file, records metadata in SQLite, and updates the catalog. The catalog serial is `max(now, last + 1)` and is stored as the file mtime. NSD is not reloaded. It learns the new member from the catalog transfer. The AXFR service builds wire from the JSON file on each transfer.

## Processes

| Process | How it runs | Role |
| --- | --- | --- |
| REST API | gunicorn, `GUNICORN_WORKERS` (default 3) | Admission and DNSSEC validation, unchanged. Caches DNSKEYs already validated to the ICANN or Handshake root. Spools the zone document. |
| Zone controller | one process | Polls the spool, ignores empty files, directories and hidden names, re-checks the SOA serial, installs the zone, ages out zones expired for more than 90 days. |
| DNS UDP | one process | Reloads the catalog on mtime change, answers SOA from the catalog, sends NOTIFY for the catalog and for new or updated zones. |
| DNS TCP | pre-fork, `axfr_children` (default 5) | `select` then `accept` on a non-blocking `127.0.0.1` socket. A failed accept is retried. Builds each user-zone AXFR from its JSON file. The catalog AXFR is the pre-built RFC 9432 payload. Each child refreshes the valid-zone list when the catalog file changes. |
| NSD | one process | Public port 53. Configured with only the catalog zone (`catalog: consumer`). Member zones come from that catalog and are stored with `zonefile: "%1/%2/%s.zone"`. Writes those files every 60 seconds, loads them on restart, then checks SOA. Remote control listens on `127.0.0.1:8952`. |
| cron | busybox `crond -S` | Every 15 minutes, deletes empty spool files and orphaned `tmp` files older than five minutes. Messages go to syslog. |

## Secondaries

NOTIFY is UDP, from the UDP service: the catalog first when its serial changes, then each new or updated member. NSD's `notify` lines are generated from the secondary list. `provide-xfr` lines are generated from that list and from `axfr_allow`, on the catalog zone and on the member pattern. NSD itself requests only AXFR (`request-xfr: AXFR`) from `127.0.0.1:5353`. Public AXFR is answered by NSD, not by the hidden TCP service. A bad TSIG on NSD's side is refused. TSIG is configured on each secondary (key name, secret or `tsig_secret_file`, and algorithm). There is no global TSIG key. `axfr_allow` entries use `NOKEY`.

The catalog is schema version 2 (`version.<catalog> TXT "2"`, member PTRs at `<label>.zones.<catalog>`). It is not signed. The tests speak AXFR with dnspython. NSD on port 53 is what a real secondary talks to.

The 90-day clear-out runs in the zone controller. Removing a zone updates the catalog; the UDP service notifies the catalog only.

## Push a zone you signed yourself

`tools/zone_push.py` is a maintainer utility. It is not copied into the container image. It does not sign zones and it does not change admission: the service still accepts only a full-zone `POST /api/v1/zones/{apex}` with `dnsauth#signedZone` JSON. The tool turns a master file, or an AXFR, into that JSON and sends it. A later file with a higher SOA serial is just another POST.

Install dnspython with the development requirements, then:

```sh
pip install -r requirements-dev.txt

# Print the JSON and do not contact the service. Stdout is only the document.
python3 tools/zone_push.py --zone-file /tmp/user.example.zone --dry-run

# POST it. The status and the service's JSON body are printed.
python3 tools/zone_push.py \
  --zone-file /tmp/user.example.zone \
  --base-url http://127.0.0.1:80

# Take the zone from an AXFR, then ask NSD whether the SOA serial matches.
python3 tools/zone_push.py \
  --axfr-zone user.example. \
  --axfr-server 192.0.2.53 \
  --axfr-port 53 \
  --tsig-key-name transfer.example. \
  --tsig-secret 'BASE64SECRET' \
  --base-url http://127.0.0.1:80 \
  --verify \
  --dns-server 127.0.0.1 \
  --dns-port 53
```

If the master file has no `$ORIGIN`, pass `--apex user.example.`. `--dry-run` writes a `request_id` on stderr so stdout stays valid JSON. A failed admission check is a non-zero exit and the HTTP status plus the JSON error body on stdout.

## Tests

```sh
pip install -r requirements-dev.txt
python3 -m pytest
```

The tests generate and sign fixture zones (algorithm 13 and 15, NSEC3). They do not use the network. GitHub Actions runs the tests, ruff (pyflakes), and a read-only container boot that checks HTTP, the public DNS port, and an empty `docker diff`.

Dev dependencies are pip-installed on the workstation and in CI. The image does not use pip: Alpine 3.24 supplies `py3-flask`, `py3-gunicorn`, `py3-dnspython`, `py3-cryptography`, and `py3-yaml`.

## Decisions

* **Secondary in CI.** dnspython performs AXFR in the tests. The container runs NSD as the relay. No Knot or BIND container.
* **Limits.** 1 MiB body, 2000 RRsets, 1000 names, 4096-byte rdata, 30 uploads per IP per minute, 15 parent lookups per IP per minute.
* **Extra parent NS names.** The apex NS set and the parent delegation must be equal, and both must include every `service_ns`. An extra name at the parent fails `ns_set_mismatch` unless the apex has it too.
* **DS digests.** SHA-256 only, unless `ds_digest_types` lists more (1 = SHA-1, 4 = SHA-384).
* **Remaining RRSIG lifetime.** A signature only has to be valid now (`rrsig_min_remaining_seconds` defaults to 0). Lifetime is at most 30 days.
* **Negative cache.** 60 seconds, one entry per apex (the latest parent-check failure).
* **Apex text.** Trim, IDNA, lowercase, one trailing dot. The URL apex and the JSON apex must match after that.
* **Glue.** `glue_missing` is returned before a parent query.
* **Handshake.** Off unless both handshake settings are provided.
* **Parent chain failures.** A parent that answers with no delegation NS is `parent_chain_invalid` (403): the message says the parent served no delegation for that name. Parent nameservers that cannot be reached, and a nameserver that answers with SERVFAIL or another non-answer, are `parent_lookup_unavailable` (503). The message says which of those happened. A resolver SERVFAIL is not reported as a parent answer. A resolver outage does not start the drift clock.
* **Drop.** Removing a zone notifies the catalog only.
* **SOA** on the master is for NSD and for polling. Public clients use NSD.

## Not in this MVP

* IXFR from the Python master (NOTIMP). NSD falls back to AXFR.
* More than one hidden primary.
* A bundled secondary beside NSD.
* Re-checking individual RRsets against the previous zone (the serial is the replay control).
* The phone app, enrolment, and JWS verification.
* TLS on this container.

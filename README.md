> :warning: Mostly slop.

# mulprox

Mullvad HTTP proxy. Per-request IP rotation. SOCKS5 server. Multi-hop chaining.

## Prerequisites

Be on a machine connected to Mullvad.

## Usage

```bash
mulprox serve

export HTTP_PROXY=http://localhost:8080
curl https://ipinfo.io
```

Global: `--config <path>` (auto-loads `./mulprox.yaml`), `--timeout` (10s).

See `mulprox -h` for all commands.

## Filter

Put params in proxy URL userinfo. Random server if none given.

| Key | Example |
|-----|---------|
| `country` | `country=Sweden` (URL-encode spaces: `South%20Africa`) |
| `city` | `city=Stockholm` |
| `seed` | `seed=12345` (deterministic) |
| `owned` | `owned=true` |
| `provider` | `provider=M247` |
| `speed` | `speed=1000` (Mbps min) |
| `multihop` | `multihop=true` |

Keys case-insensitive. Bools: `true/false`, `yes/no`, `1/0`. Empty password ignored.

```bash
export HTTP_PROXY=http://country=Sweden,owned=true:@localhost:8080
curl https://ipinfo.io
```

Filter flags (`--country`, `--city`, ...) work on all subcommands. On `serve` they set base filter for all requests.

## SOCKS5 & Multi-Hop

```bash
mulprox serve --socks5-port 1080
curl --socks5-hostname localhost:1080 https://ipinfo.io
```

SOCKS5 username = connection string (password ignored). Both NO_AUTH and user/pass (0x02) accepted.

```bash
curl --socks5-hostname localhost:1080 --proxy-user "country=Sweden:" https://ipinfo.io
```

Upstream chaining:

```bash
# Mullvad -> upstream -> target
mulprox serve --upstream-socks5 socks5.example.com:1080

# bypasses Mullvad, connects directly (useful for testing / local nodes)
mulprox serve --upstream-socks5 direct://127.0.0.1:1080
```
```
client -> A (HTTP) -> direct:// -> B (SOCKS5) -> Mullvad -> target
```
`SOCKS5_PROXY` env = fallback for `--upstream-socks5`.

## Config & Env

YAML config (`--config` or `./mulprox.yaml`):

```yaml
host: "127.0.0.1"
port: 3128
https-only: true
socks5-port: 1080
upstream-socks5: "socks5.example.com:1080"
country: ["Sweden"]
debug: true
```

| Env | |
|-----|---|
| `FAST_HEALTH_CHECK` | `true` -> probe servers at startup for fast online pick |

All flags bind to env via viper.

## Observability

| Path | |
|------|----|
| `/healthz` | Liveness (`{"status":"ok"}`) |
| `/readyz` | Readiness (503 if 0 online servers) |
| `/dashboard` | HTML dashboard |
| `/dashboard/stats` | JSON stats API |
| `/dashboard/proxies` | Server table (health, latency, req counts) |

Health checker probes all servers every 30s. Offline after 2 fails, back after 3 successes.

Retry: 3 retries on transient errors. Bodies <=10MB buffered for replay.

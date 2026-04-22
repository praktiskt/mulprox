# mulprox

Mullvad HTTP proxy service with per-request IP rotation.

## Usage

```bash
# Start proxy server
mulprox serve

# Set HTTP_PROXY and make requests
export HTTP_PROXY=http://localhost:8080
curl https://ipinfo.io
```

## Request Configuration

Control server selection using connection strings in the proxy URL. Parameters are comma-separated key=value pairs in the URL userinfo section.

If no parameters are provided, a random Mullvad server is selected automatically for each request.

| Parameter | Description | Example |
|-----------|-------------|---------|
| `country` | Filter by country | `country=Sweden` |
| `city` | Filter by city | `city=Stockholm` |
| `seed` | Deterministic server selection. Same seed = same server. No seed = random. | `seed=12345` |
| `owned` | Only Mullvad-owned servers | `owned=true` |
| `provider` | Filter by hosting provider | `provider=M247` |
| `speed` | Minimum server speed (Mbps) | `speed=1000` |
| `multihop` | Allow multihop servers | `multihop=true` |

### Notes

- Parameter keys are **case-insensitive** (`Country`, `country`, `COUNTRY` all work)
- Values are **URL-encoded** to handle spaces (e.g., `country=South%20Africa`)
- Boolean values accept: `true`/`false`, `yes`/`no`, `1`/`0` (case-insensitive)
- Empty password is ignored (format: `http://params:@host:port`)

### Examples

```bash
# Route through Sweden
export HTTP_PROXY=http://country=Sweden:@localhost:8080
curl https://ipinfo.io

# Deterministic IP (same seed = same server)
export HTTP_PROXY=http://seed=12345:@localhost:8080
curl https://ipinfo.io

# Combine filters
export HTTP_PROXY=http://country=Sweden,owned=true:@localhost:8080
curl https://ipinfo.io

# Country with spaces (URL-encoded)
export HTTP_PROXY=http://country=South%20Africa:@localhost:8080
curl https://ipinfo.io

# Case-insensitive parameters
export HTTP_PROXY=http://COUNTRY=sweden,SPEED=1000:@localhost:8080
curl https://ipinfo.io
```

## Multi-Hop & SOCKS5

Mulprox can chain through another SOCKS5 proxy and also expose a SOCKS5 server itself.

### SOCKS5 Server Mode

Run a SOCKS5 server alongside the HTTP proxy. Each connection routes through a fresh Mullvad server.

```bash
mulprox serve --socks5-port 1080
# Client connects directly via SOCKS5
curl --socks5-hostname localhost:1080 https://ipinfo.io
```

### Upstream SOCKS5 Chaining

Route the HTTP proxy through an upstream SOCKS5 proxy. The upstream can be another mulprox instance, any SOCKS5 server, or a `direct://` address for local/LAN chaining.

```bash
# Chain through another SOCKS5 proxy
mulprox serve --upstream-socks5 socks5.example.com:1080

# Or via environment variable
SOCKS5_PROXY=socks5.example.com:1080 mulprox serve
```

**With `direct://` prefix**, the upstream connection bypasses Mullvad entirely. Useful when the upstream is on the same LAN or localhost and cannot be reached through Mullvad.

```bash
# Instance B: SOCKS5 server
mulprox serve --socks5-port 1080

# Instance A: HTTP proxy, chains directly to B
mulprox serve --upstream-socks5 direct://127.0.0.1:1080
```

Full multi-hop chain:
```
client → A (HTTP proxy) → direct:// → B (SOCKS5 server) → Mullvad → target
```

## Commands

- `mulprox serve` - Start HTTP proxy server
- `mulprox list` - List Mullvad servers
- `mulprox get <url>` - Fetch URL through Mullvad
- `mulprox --check-mullvad` - Check local Mullvad status

## Docker

```bash
docker build -t mulprox .
docker run -p 8080:8080 mulprox serve
```

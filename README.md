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

## Request Headers

Control server selection using `X-Mulprox-*` headers:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Mulprox-Country` | Filter by country | `Sweden`, `Germany` |
| `X-Mulprox-City` | Filter by city | `Stockholm`, `Berlin` |
| `X-Mulprox-Owned` | Only Mullvad-owned servers | `true` or `false` |
| `X-Mulprox-Provider` | Filter by hosting provider | `M247`, `Leaseweb` |
| `X-Mulprox-Speed` | Minimum server speed (Mbps) | `1000` |
| `X-Mulprox-Multihop` | Allow multihop servers | `true` or `false` |
| `X-Mulprox-Seed` | Deterministic server selection | `12345` |

Examples:

```bash
# Route through Sweden
curl -H "X-Mulprox-Country: Sweden" http://localhost:8080/https://ipinfo.io

# Deterministic IP (same seed = same server)
curl -H "X-Mulprox-Seed: 12345" http://localhost:8080/https://ipinfo.io

# Combine filters
curl -H "X-Mulprox-Country: Sweden" -H "X-Mulprox-Owned: true" http://localhost:8080/https://ipinfo.io
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

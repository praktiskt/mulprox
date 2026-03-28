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

Control server selection using the `Proxy-Authorization` header with JSON. This works for both HTTP and HTTPS (CONNECT) requests.

If no `Proxy-Authorization` header is provided, a random Mullvad server is selected automatically for each request.

| Field | Description | Example |
|-------|-------------|---------|
| `country` | Filter by country | `"Sweden"` |
| `city` | Filter by city | `"Stockholm"` |
| `seed` | Deterministic server selection. Same seed = same server. No seed = random. | `12345` |
| `owned` | Only Mullvad-owned servers | `true` |
| `provider` | Filter by hosting provider | `"M247"` |
| `speed` | Minimum server speed (Mbps) | `1000` |
| `multihop` | Allow multihop servers | `true` |

### Examples

```bash
# Route through Sweden
curl --proxy-header "Proxy-Authorization: {\"country\":\"Sweden\"}" https://ipinfo.io

# Deterministic IP (same seed = same server)
curl --proxy-header "Proxy-Authorization: {\"seed\":12345}" https://ipinfo.io

# Combine filters
curl --proxy-header "Proxy-Authorization: {\"country\":\"Sweden\",\"owned\":true}" https://ipinfo.io
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

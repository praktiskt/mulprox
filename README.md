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

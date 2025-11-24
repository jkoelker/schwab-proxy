# Schwab API OAuth2 Proxy

OAuth2 proxy for the Schwab Trading API that allows multiple clients to share
a single Schwab connection (personal project limitation). Acts as both a
Schwab API client and OAuth2 server for your applications.

## Quick Start

### Using Containers (Podman or Docker)

```bash
# First, generate secure seeds (do this once and save them securely)
openssl rand -hex 32  # For STORAGE_SEED
openssl rand -hex 32  # For JWT_SEED

# Run with Podman
podman run -d \
  -p 8080:8080 \
  -v schwab-data:/data \
  -e STORAGE_SEED="your-saved-storage-seed" \
  -e JWT_SEED="your-saved-jwt-seed" \
  -e SCHWAB_CLIENT_ID="your-schwab-client-id" \
  -e SCHWAB_CLIENT_SECRET="your-schwab-client-secret" \
  -e SCHWAB_REDIRECT_URI="https://127.0.0.1:8080/setup/callback" \
  ghcr.io/jkoelker/schwab-proxy:latest

# Or with Docker
docker run -d \
  -p 8080:8080 \
  -v schwab-data:/data \
  -e STORAGE_SEED="your-saved-storage-seed" \
  -e JWT_SEED="your-saved-jwt-seed" \
  -e SCHWAB_CLIENT_ID="your-schwab-client-id" \
  -e SCHWAB_CLIENT_SECRET="your-schwab-client-secret" \
  -e SCHWAB_REDIRECT_URI="https://127.0.0.1:8080/setup/callback" \
  ghcr.io/jkoelker/schwab-proxy:latest
```

**Important**: Save your seeds securely! The same seeds must be used on every
restart or your encrypted data will be inaccessible.

Visit `https://127.0.0.1:8080/setup` to authenticate with Schwab.

To get the admin API key (if not specified):
```bash
# For Podman
podman exec $(podman ps -q -f ancestor=ghcr.io/jkoelker/schwab-proxy:latest) cat /data/admin_api_key

# For Docker
docker exec $(docker ps -q -f ancestor=ghcr.io/jkoelker/schwab-proxy:latest) cat /data/admin_api_key
```

## Using schwab-py

The proxy works seamlessly with schwab-py using the provided patcher:

```python
# Import and apply the patcher before importing schwab modules
import schwab_monkeypatch

schwab_monkeypatch.patch_schwab_client(
    "https://127.0.0.1:8080",  # Your proxy URL
    verify_ssl=False          # Set to False for self-signed certificates
)

# Now import and use schwab-py normally
import schwab
from schwab.auth import client_from_manual_flow

client = client_from_manual_flow(
    api_key='proxy_client_id',      # Client ID from proxy
    app_secret='proxy_client_secret', # Client secret from proxy
    callback_url='https://localhost:3000/callback',
    token_path='/tmp/token.json'
)

# All API calls now go through the proxy
response = client.get_account_numbers()
accounts = response.json()
```

See `python/test_client.py` for a complete example including command-line usage.

## Client Management (API & CLI)

### Create a Client

```bash
# Set admin API key (if configured)
export ADMIN_API_KEY="your-admin-key"

# Create a new client
curl -k -X POST https://127.0.0.1:8080/api/clients \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Trading App",
    "redirect_uri": "https://localhost:3000/callback"
  }'

# Response includes client_id and client_secret (only shown once!)
{
  "id": "client_abc123",
  "secret": "secret_xyz789",
  "name": "My Trading App",
  "redirect_uri": "https://localhost:3000/callback"
}
```

### List Clients

```bash
curl -k -X GET https://127.0.0.1:8080/api/clients \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

### Delete a Client

```bash
curl -k -X DELETE https://127.0.0.1:8080/api/clients/client_abc123 \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

### Manage Clients with the Built-in CLI

The `schwab-proxy` binary includes admin subcommands, so you don't have to
handcraft curl calls. It reads your proxy URL and admin key from env vars:

- `SCHWAB_PROXY_URL` (default `https://127.0.0.1:8080`)
- `ADMIN_API_KEY` (required)
- `SCHWAB_PROXY_INSECURE` (set to `true` to skip TLS verification for local/self-signed)

Examples:

```bash
# List clients (table)
schwab-proxy clients list

# Create a client (prints id + secret)
schwab-proxy clients create \
  --name "My App" \
  --redirect-uri "https://localhost:3000/callback" \
  --scopes "marketdata,accounts"

# Same, JSON output
SCHWAB_PROXY_URL=https://proxy.example.com \
ADMIN_API_KEY=$(cat /data/admin_api_key) \
schwab-proxy clients create --name "Prod" --redirect-uri "https://app/cb" --json

# Update and deactivate a client
schwab-proxy clients update --id client_abc123 --inactive

# Delete a client
schwab-proxy clients delete --id client_abc123
```

## API Examples

### Direct API Calls

Once authenticated, you can make direct API calls through the proxy:

```bash
# Get account numbers
curl -k https://127.0.0.1:8080/trader/v1/accounts/accountNumbers

# Get quotes
curl -k "https://127.0.0.1:8080/marketdata/v1/quotes?symbols=AAPL,MSFT"

# Get option chain
curl -k "https://127.0.0.1:8080/marketdata/v1/chains?symbol=AAPL"

# Check proxy health
curl -k https://127.0.0.1:8080/health/ready
```

Note: The `-k` flag bypasses certificate warnings for local development.


### Manual Authorization Approval

If `AUTO_APPROVE_AUTHORIZATION=false`, client authorizations require admin
approval:

```bash
# View pending approvals
curl -k https://127.0.0.1:8080/api/approvals \
  -H "Authorization: Bearer $ADMIN_API_KEY"

# Approve authorization
curl -k -X POST https://127.0.0.1:8080/api/approvals/APPROVAL_ID \
  -H "Authorization: Bearer $ADMIN_API_KEY"

# Deny authorization
curl -k -X DELETE https://127.0.0.1:8080/api/approvals/APPROVAL_ID \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

## Configuration

### Required Environment Variables

- `STORAGE_SEED` - Seed for storage encryption (generate
     with `openssl rand -hex 32`)
- `JWT_SEED` - Seed for JWT signing (generate with `openssl rand -hex 32`)
- `SCHWAB_CLIENT_ID` - From Schwab developer portal
- `SCHWAB_CLIENT_SECRET` - From Schwab developer portal
- `SCHWAB_REDIRECT_URI` - Must match Schwab app config (e.g.
    `https://127.0.0.1:8080/setup/callback`)

### Optional Variables

- `ADMIN_API_KEY` - API key for admin endpoints (if not set, a random key will
    be generated and saved to `$DATA_PATH/admin_api_key`)
- `DEBUG_LOGGING` - Enable verbose logging (default: false)
- `AUTO_APPROVE_AUTHORIZATION` - Auto-approve client auth requests
    (default: true)
- `PORT` - Listen port (default: 8080)
- `DATA_PATH` - Data directory for database and config files (default: `/data`
    in container, `./data` when running directly)
- `TLS_CERT_PATH` / `TLS_KEY_PATH` - Custom TLS certificates
    (default: self-signed)

## Building from Source

```bash
# Build
go build -o schwab-proxy ./cmd/schwab-proxy

# Or use the helper script to generate keys
go run scripts/generate_keys.go

# Run tests
go test ./...

# Run with devkit container
make devkit
```

## Production Notes

- **Single Instance Only**: Schwab personal projects allow only one connection
- Use proper TLS certificates (via `TLS_CERT_PATH` and `TLS_KEY_PATH`)
- Store seeds in a secrets manager (Kubernetes secrets, AWS Secrets Manager)
- Data is encrypted with AES-256 using keys derived from your seeds
- Supports automatic TLS certificate reloading for Kubernetes deployments

### Health Checks

The proxy provides Kubernetes-compatible health endpoints:

- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe

## License

MIT

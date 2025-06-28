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
  -e SCHWAB_REDIRECT_URI="https://localhost:8080/auth/callback" \
  ghcr.io/jkoelker/schwab-proxy:latest

# Or with Docker
docker run -d \
  -p 8080:8080 \
  -v schwab-data:/data \
  -e STORAGE_SEED="your-saved-storage-seed" \
  -e JWT_SEED="your-saved-jwt-seed" \
  -e SCHWAB_CLIENT_ID="your-schwab-client-id" \
  -e SCHWAB_CLIENT_SECRET="your-schwab-client-secret" \
  -e SCHWAB_REDIRECT_URI="https://localhost:8080/auth/callback" \
  ghcr.io/jkoelker/schwab-proxy:latest
```

**Important**: Save your seeds securely! The same seeds must be used on every
restart or your encrypted data will be inaccessible.

Visit `https://localhost:8080/setup` to authenticate with Schwab.

To get the admin API key (if not specified):
```bash
# For Podman
podman exec $(podman ps -q -f ancestor=ghcr.io/jkoelker/schwab-proxy:latest) cat /data/admin_api_key

# For Docker
docker exec $(docker ps -q -f ancestor=ghcr.io/jkoelker/schwab-proxy:latest) cat /data/admin_api_key
```

## Using schwab-py

The proxy works seamlessly with schwab-py by monkey-patching the base URLs:

```python
import schwab

# Monkey patch schwab-py to use your proxy
schwab.client.base.SCHWAB_BASE_URL = 'https://localhost:8080'
schwab.auth.SCHWAB_AUTH_BASE_URL = 'https://localhost:8080/v1/oauth'

# Then use schwab-py normally
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

## Client Management

### Create a Client

```bash
# Set admin API key (if configured)
export ADMIN_API_KEY="your-admin-key"

# Create a new client
curl -k -X POST https://localhost:8080/api/clients \
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
curl -k -X GET https://localhost:8080/api/clients \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

### Delete a Client

```bash
curl -k -X DELETE https://localhost:8080/api/clients/client_abc123 \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

## API Examples

### Direct API Calls

Once authenticated, you can make direct API calls through the proxy:

```bash
# Get account numbers
curl -k https://localhost:8080/trader/v1/accounts/accountNumbers

# Get quotes
curl -k "https://localhost:8080/marketdata/v1/quotes?symbols=AAPL,MSFT"

# Get option chain
curl -k "https://localhost:8080/marketdata/v1/chains?symbol=AAPL"

# Check proxy status
curl -k https://localhost:8080/status
```

Note: The `-k` flag bypasses certificate warnings for local development.


### Manual Authorization Approval

If `AUTO_APPROVE_AUTHORIZATION=false`, client authorizations require admin
approval:

```bash
# View pending approvals
curl -k https://localhost:8080/api/approvals \
  -H "Authorization: Bearer $ADMIN_API_KEY"

# Approve authorization
curl -k -X POST https://localhost:8080/api/approvals/APPROVAL_ID \
  -H "Authorization: Bearer $ADMIN_API_KEY"

# Deny authorization
curl -k -X DELETE https://localhost:8080/api/approvals/APPROVAL_ID \
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
    `https://localhost:8080/auth/callback`)

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

## License

MIT

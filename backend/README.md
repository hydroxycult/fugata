# Fugata Backend

**Production-ready encrypted ephemeral secret-delivery backend in Rust.**

Fugata provides secure, time-limited secret sharing with strong cryptographic guarantees:

- **AES-256-GCM encryption** for all stored secrets
- **Envelope encryption** with configurable KMS providers (Local, Vault, AWS KMS)
- **Argon2id hashing** for deletion tokens with pepper
- **One-time secrets** that self-destruct after first access
- **Token replay protection** with constant-time verification
- **Rate limiting** per IP address
- **Audit logging** for all operations
- **Zero-knowledge architecture** - plaintext never logged or cached

## Quick Start

### Prerequisites

- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- SQLite or PostgreSQL
- (Optional) Vault or AWS KMS for production

### Build

```bash
cd backend
cargo build --release
```

### Configure

```bash
cp .env.example .env
# Edit .env and set PEPPER and KMS_LOCAL_KEY (see instructions in file)
```

**Generate secrets:**

```bash
# PEPPER (32 bytes hex)
openssl rand -hex 32

# KMS_LOCAL_KEY (32 bytes base64)
openssl rand -base64 32

# IP_HASH_KEY (32 bytes hex)
openssl rand -hex 32
```

### Run

```bash
cargo run --release
```

Server starts on `http://localhost:8080`.

## Usage

### Create a Secret

```bash
curl -X POST http://localhost:8080/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "content": "My secret message",
    "duration": "1h",
    "one_time": false
  }'
```

Response:
```json
{
  "id": "fug_AbCd1234...",
  "deletion_token": "dt_XyZ9876...",
  "expires_at": "2025-11-30T12:00:00Z"
}
```

**IMPORTANT:** Save the `deletion_token` - it cannot be retrieved later!

### Retrieve a Secret

```bash
curl http://localhost:8080/secrets/fug_AbCd1234...
```

Response:
```json
{
  "id": "fug_AbCd1234...",
  "content": "My secret message",
  "created_at": "2025-11-30T11:00:00Z",
  "expires_at": "2025-11-30T12:00:00Z"
}
```

### Delete a Secret

```bash
curl -X DELETE http://localhost:8080/secrets/fug_AbCd1234... \
  -H "X-Deletion-Token: dt_XyZ9876..."
```

Response:
```json
{
  "message": "Secret deleted successfully"
}
```

### Health Check

```bash
curl http://localhost:8080/healthz
```

## Configuration

See [.env.example](./env.example) for all configuration options.

### Key Options

- **TTL_PRESETS**: Allowed expiration durations (`5m`, `1h`, `24h`, `168h`)
- **MAX_SECRET_SIZE**: Maximum secret size in bytes (default: 10MB)
- **ARGON2_TIME**, **ARGON2_MEMORY**: Tune hash security vs performance
- **LRU_CACHE_SIZE**: Number of encrypted secrets to cache
- **KMS_FAIL_CLOSED**: Refuse startup if KMS unavailable (recommended: `true`)

### KMS Providers

**Local** (development):
```bash
KMS_LOCAL_KEY=<base64-key>
```

**Vault** (production):
```bash
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=<token>
VAULT_MOUNT=transit
VAULT_KEY_NAME=fugata-kek
```

**AWS KMS** (production, requires `--features aws-kms`):
```bash
cargo build --features aws-kms
AWS_REGION=us-east-1
AWS_KMS_KEY_ID=<kms-key-id>
```

## Testing

### Unit Tests

```bash
cargo test --lib
```

Fast tests (<10s) for crypto primitives, utilities, and core logic.

### Integration Tests

```bash
cargo test --test integration
```

Full end-to-end tests with in-memory SQLite and real crypto flows.

### All Tests

```bash
cargo test
```

## Security Model

### Encryption

- Each secret gets a unique **32-byte Data Encryption Key (DEK)**
- DEK encrypts content using **AES-256-GCM**
- DEK is wrapped by **Key Encryption Key (KEK)** managed by KMS
- All encryption includes **Additional Authenticated Data (AAD)** with secret ID
- DEKs are **zeroized** immediately after use

### Deletion Tokens

- **32-byte cryptographically random** tokens
- Hashed with **Argon2id** + **32-byte pepper**
- **Constant-time verification** prevents timing attacks
- **Replay protection** tracks used tokens for 1 hour
- **Never logged** in plaintext

### Privacy

- Client IPs are **hashed with HMAC-SHA256** before storage
- Plaintext secrets **never logged**, cached, or written to disk unencrypted
- Audit logs contain only **hashed IPs** and **secret IDs** (not content)

### Runtime KMS Failure Semantics

**FAIL-CLOSED BEHAVIOR:** All operations requiring KMS **immediately fail** with `503 Service Unavailable` if KMS becomes unavailable at runtime. **No partial writes, no state mutations, no side effects.**

#### Behavior Per Operation

**CREATE (POST /secrets)**
- KMS failure during DEK wrapping → Returns `503`
- **Guaranteed no side effects:**
  - No database insert
  - No deletion token creation
  - No audit "create" event
  - No cache writes
- **Safe to retry** once KMS recovers

**GET (GET /secrets/:id)**
- KMS failure during DEK unwrap → Returns `503`
- **Guaranteed no mutations:**
  - One-time secrets NOT marked as "used"
  - No database updates
  - No cache invalidation
  - No audit "get" event
- **Safe to retry** - secret remains intact

**DELETE (DELETE /secrets/:id)**
- **Does NOT use KMS** (only verifies Argon2 hash)
- **Works normally even during KMS outage**
- Deletion tokens can still be validated

#### Operational Guidance

1. **Expected Behavior:**
   - All CREATE and GET requests return `503` during KMS outage
   - DELETE operations continue working normally
   - Health check (`/healthz`) reports KMS failure

2. **Monitoring & Alerts:**
   - Monitor for sustained `503` responses on `/secrets` endpoints
   - Alert on KMS connection failures (logged as errors)
   - Track KMS latency metrics (p95, p99)

3. **Recovery:**
   - **No data loss** - all secrets remain intact in database
   - **No corruption** - fail-closed prevents partial writes
   - **Immediate recovery** - operations resume once KMS is available
   - **No manual intervention** required

4. **Client Retry Strategy:**
   - Retry GET requests with exponential backoff
   - Retry CREATE requests (idempotent - will fail-fast until KMS recovers)
   - Set retry budget (e.g., 3 attempts over 30 seconds)

5. **Multi-Instance Considerations:**
   - KMS failures are independent per instance
   - Load balancer should route around unhealthy instances
   - Use health check endpoint for load balancer health probes

**Testing:** Runtime KMS failure behavior is verified in `tests/kms_runtime_fail.rs` with:
- Encrypt failures (no DB/cache pollution)
- Decrypt failures (one-time secrets not burned)
- 503 status code mapping
- Zero side effects on all failures



## API Reference

### POST /secrets

Create a new secret.

**Request:**
```json
{
  "content": "string (required)",
  "duration": "5m|1h|24h|168h (optional, default: 1h)",
  "one_time": "boolean (optional, default: false)",
  "metadata": "object (optional)"
}
```

**Response (201):**
```json
{
  "id": "fug_...",
  "deletion_token": "dt_...",
  "expires_at": "ISO 8601 timestamp"
}
```

### GET /secrets/:id

Retrieve a secret. One-time secrets are deleted after first access.

**Response (200):**
```json
{
  "id": "fug_...",
  "content": "string",
  "created_at": "ISO 8601 timestamp",
  "expires_at": "ISO 8601 timestamp",
  "metadata": "object (if provided)"
}
```

### DELETE /secrets/:id

Delete a secret using deletion token.

**Headers:**
- `X-Deletion-Token: dt_...`

**Response (200):**
```json
{
  "message": "Secret deleted successfully"
}
```

### GET /healthz

Health check for database, KMS, and cache.

**Response (200):**
```json
{
  "status": "healthy",
  "checks": {
    "database": "ok",
    "kms": "ok",
    "cache": "ok"
  }
}
```

## Production Deployment

1. **Use production KMS** (Vault or AWS KMS, not local key)
2. **Enable fail-closed mode** (`KMS_FAIL_CLOSED=true`)
3. **Use PostgreSQL** for multi-instance deployments
4. **Set up HTTPS** (use nginx or cloud load balancer)
5. **Enable structured logging** (`LOG_LEVEL=info`, JSON output)
6. **Monitor**:
   - Health endpoint (`/healthz`)
   - Cache hit rate (logs)
   - Cleanup job runs (logs)
7. **Rotate secrets**:
   - PEPPER rotation invalidates all deletion tokens
   - KEK rotation requires data migration

## Architecture

```
Client → [HTTPS] → API Layer (Axum)
                      ↓
              Service Layer (Orchestration)
                      ↓  
        ┌─────────────┼─────────────┐
        ↓             ↓             ↓
    Crypto        Hasher Pool    KMS Layer
  (AES-256-GCM)   (Argon2id)  (Local/Vault/AWS)
        ↓             ↓             ↓
        └─────────────┼─────────────┘
                      ↓
              Database (SQLite/PostgreSQL)
```

**Layers:**
- **API**: HTTP handlers, rate limiting, timeouts
- **Service**: Business logic, orchestration
- **Crypto**: Encryption/decryption with DEK management
- **KMS**: KEK management and DEK wrapping
- **Hasher**: Argon2 worker pool with backpressure
- **Cache**: LRU cache for encrypted blobs + replay protection
- **Database**: Persistent storage with migrations

## TODO (Future Features - P2)

These features are **not implemented** and left for future enhancement:

- [ ] Multi-region replication
- [ ] Multi-tenant org mode
- [ ] Webhooks
- [ ] ASN/Geo/time-window access rules
- [ ] Policy engine
- [ ] Client-side encryption

## Contributing

1. Run tests: `cargo test`
2. Run clippy: `cargo clippy -- -D warnings`
3. Format code: `cargo fmt`
4. Security audit: `cargo audit`

## License

MIT License - See LICENSE file for details.

## Security

For security vulnerabilities, please email security@example.com (do not create public issues).

## Credits

Built with:
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [SQLx](https://github.com/launchbadge/sqlx) - Database toolkit
- [RustCrypto](https://github.com/RustCrypto) - Cryptography
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Password hashing

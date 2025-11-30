# Fugata Configuration Reference

Complete guide to all configuration options.


## Table of Contents

- [Environment Variables](#environment-variables)
- [Database Configuration](#database-configuration)
- [KMS Configuration](#kms-configuration)
- [Security Configuration](#security-configuration)
- [Performance Tuning](#performance-tuning)
- [Development vs Production](#development-vs-production)
- [Configuration Examples](#configuration-examples)


## Environment Variables

All configuration via `.env` file or exported environment variables.

### Loading Priority

1. Environment variables (highest priority)
2. `.env` file in working directory
3. Defaults (if applicable)

**Example:**
```bash
# .env file
DATABASE_URL=sqlite://fugata.db

# Override via environment
export DATABASE_URL=postgresql://user:pass@localhost/fugata
cargo run  # Uses PostgreSQL, not SQLite
```


## Database Configuration

### DATABASE_URL

**Required:** Yes<br>
**Type:** String (connection URL)<br>
**Default:** None<br>

**Format:**

SQLite:
```
sqlite://path/to/database.db
sqlite::memory:  # In-memory (testing only)
```

PostgreSQL:
```
postgresql://username:password@host:port/database
postgresql://username:password@host/database?sslmode=require
```

**Examples:**
```bash
# Local SQLite (development)
DATABASE_URL=sqlite://./fugata.db

# Local PostgreSQL
DATABASE_URL=postgresql://fugata:password@localhost/fugata

# Remote PostgreSQL with SSL
DATABASE_URL=postgresql://user:pass@db.example.com/fugata?sslmode=require

# With connection pool settings
DATABASE_URL=postgresql://user:pass@localhost/fugata?max_connections=25

# Unix socket
DATABASE_URL=postgresql:///fugata?host=/var/run/postgresql
```

**Security:**
- Use strong database passwords (16+ characters)
- Enable SSL for remote connections (`sslmode=require`)
- Restrict database user permissions (grant only necessary privileges)
- Store DATABASE_URL in secrets manager (not .env in production)

**Performance:**
- Use connection pooling (controlled by `DB_MAX_CONNECTIONS`)
- For high traffic, increase PostgreSQL `max_connections` setting
- SQLite: Limited concurrency, use PostgreSQL for production


### DB_MAX_CONNECTIONS

**Required:** No<br>
**Type:** Integer<br>
**Default:** `25`<br>
**Range:** `1-100`<br>

Maximum number of database connections in the pool.

**Tuning guide:**

| Traffic Level | Recommended Value | Notes |
|--------------|-------------------|-------|
| Low (< 10 req/s) | 5-10 | Saves resources |
| Medium (10-50 req/s) | 25 (default) | Balanced |
| High (50-200 req/s) | 50-75 | Check DB server limits |
| Very High (200+ req/s) | 75-100 | May need multiple instances |

**Formula:** `connections = concurrent_requests × 1.5`

**Limits:**
- Cannot exceed database server's `max_connections` setting
- PostgreSQL default is 100 connections (system-wide)
- Each connection ~= 10MB RAM on PostgreSQL

**Examples:**
```bash
# Low traffic server
DB_MAX_CONNECTIONS=5

# Default (medium traffic)
DB_MAX_CONNECTIONS=25

# High traffic
DB_MAX_CONNECTIONS=75
```

**Troubleshooting:**
```
Error: FATAL: too many connections
→ Reduce DB_MAX_CONNECTIONS or increase PostgreSQL max_connections
```


### DB_QUERY_TIMEOUT_SECS

**Required:** No<br>
**Type:** Integer<br>
**Default:** `10`<br>
**Range:** `1-300`<br>

Maximum time (seconds) for database queries to complete.

**Purpose:**
- Prevents hanging queries
- Fails fast on database issues
- Releases connections sooner

**Tuning:**
```bash
# Aggressive timeout (fast SSD)
DB_QUERY_TIMEOUT_SECS=5

# Default (balanced)
DB_QUERY_TIMEOUT_SECS=10

# Tolerant (slow disks, network DB)
DB_QUERY_TIMEOUT_SECS=30
```

**Typical query times:**
- SELECT secret: 1-3ms (with index)
- INSERT secret: 2-5ms
- DELETE secret: 1-2ms

**Warning:** Setting too low causes false timeouts under load.


## KMS Configuration

### KMS_PROVIDER

**Required:** Yes<br>
**Type:** Enum string<br>
**Default:** None<br>
**Options:** `Local`, `Vault`, `Aws`<br>

Selects the Key Management Service backend.

**Comparison:**

| Provider | Use Case | KEK Storage | Rotation | Audit | Production Ready |
|----------|----------|-------------|----------|-------|------------------|
| Local | Development | Memory | No | No |  NO |
| Vault | Production | Vault/HSM | Manual | Yes |  YES |
| AWS | Production | AWS CloudHSM | Automatic | Yes |  YES |

**Examples:**
```bash
# Development only
KMS_PROVIDER=Local

# Production with Vault
KMS_PROVIDER=Vault

# Production with AWS
KMS_PROVIDER=Aws
```

** Warning:** NEVER use `Local` KMS in production!


### KMS_LOCAL_KEY

**Required:** If `KMS_PROVIDER=Local`<br>
**Type:** Base64-encoded string (~44 characters)<br>
**Default:** None<br>

Base64-encoded 256-bit encryption key for Local KMS.

**Generate:**
```bash
openssl rand -base64 32
```

**Example:**
```bash
KMS_LOCAL_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

**Security:**
-  **DEVELOPMENT ONLY**
- KEK stored in process memory (not HSM)
- No key rotation support
- Changing key makes all secrets unreadable
- Use Vault or AWS KMS for production


### Vault KMS Configuration

Required when `KMS_PROVIDER=Vault`:

#### VAULT_ADDR

**Required:** Yes (for Vault)<br>
**Type:** URL string<br>
**Default:** None<br>

Vault server address.

**Examples:**
```bash
VAULT_ADDR=https://vault.example.com:8200
VAULT_ADDR=http://localhost:8200  # Dev only
VAULT_ADDR=https://vault.internal.corp
```

**Security:**
- Always use HTTPS in production
- Verify TLS certificates
- Use internal network (not public internet)


#### VAULT_TOKEN

**Required:** Yes (for Vault)<br>
**Type:** Token string<br>
**Default:** None<br>

Vault authentication token with transit permissions.

**Generate:**
```bash
# Create policy
vault policy write fugata - <<EOF
path "transit/encrypt/fugata-kek" {
  capabilities = ["update"]
}
path "transit/decrypt/fugata-kek" {
  capabilities = ["update"]
}
EOF

# Create token
vault token create -policy=fugata -ttl=8760h
```

**Example:**
```bash
VAULT_TOKEN=s.xxxxxxxxxxxxxxxxxxxxxxxx
```

**Security:**
- Limit token TTL (renew periodically)
- Use minimal permissions (encrypt/decrypt only)
- Store token in secrets manager
- Rotate tokens regularly


#### VAULT_MOUNT

**Required:** No (for Vault)<br>
**Type:** String<br>
**Default:** `transit`<br>

Vault transit secrets engine mount point.

**Examples:**
```bash
VAULT_MOUNT=transit          # Default
VAULT_MOUNT=fugata-transit   # Custom mount
```

**Setup:**
```bash
# Enable transit engine
vault secrets enable transit

# Or at custom mount
vault secrets enable -path=fugata-transit transit
```


#### VAULT_KEY_NAME

**Required:** Yes (for Vault)<br>
**Type:** String<br>
**Default:** None<br>

Name of the encryption key in Vault transit engine.

**Examples:**
```bash
VAULT_KEY_NAME=fugata-kek
VAULT_KEY_NAME=production-kek
```

**Setup:**
```bash
# Create key
vault write -f transit/keys/fugata-kek
```


### AWS KMS Configuration

Required when `KMS_PROVIDER=Aws`:

#### AWS_KMS_KEY_ID

**Required:** Yes (for AWS)<br>
**Type:** ARN or alias string<br>
**Default:** None<br>

AWS KMS key identifier.

**Formats:**
```bash
# ARN (full)
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Key ID (short)
AWS_KMS_KEY_ID=12345678-1234-1234-1234-123456789012

# Alias
AWS_KMS_KEY_ID=alias/fugata-kek
```

**Recommendation:** Use ARN for clarity.


#### AWS_REGION

**Required:** Yes (for AWS)<br>
**Type:** AWS region string<br>
**Default:** None<br>

AWS region where KMS key resides.

**Examples:**
```bash
AWS_REGION=us-east-1
AWS_REGION=eu-west-1
AWS_REGION=ap-southeast-2
```


#### AWS_ACCESS_KEY_ID

**Required:** Yes (for AWS)<br>
**Type:** IAM access key ID<br>
**Default:** None<br>

AWS IAM credentials.

**Example:**
```bash
AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxxxxxx
```

**Security:**
- Use IAM user with minimal permissions (encrypt/decrypt only)
- Rotate keys every 90 days
- Store in secrets manager (not .env)
- Prefer IAM roles (EC2/ECS) over access keys

**IAM Policy (minimal):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```


#### AWS_SECRET_ACCESS_KEY

**Required:** Yes (for AWS)<br>
**Type:** IAM secret access key<br>
**Default:** None<br>

AWS IAM secret key.

**Example:**
```bash
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Security:** Same precautions as AWS_ACCESS_KEY_ID.


## Security Configuration

### IP_HASH_KEY

**Required:** Yes<br>
**Type:** 64 hexadecimal characters (32 bytes)<br>
**Default:** None<br>

Key for hashing IP addresses in audit logs.

**Generate:**
```bash
openssl rand -hex 32
```

**Example:**
```bash
IP_HASH_KEY=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

**Purpose:**
- IPs hashed before logging (privacy)
- Same IP → same hash (correlation)
- Different key → different hash (unlinkable)

**Security:**
- Random generation required (not password)
- Never share this key
- Rotate periodically (invalidates old audit correlation)
- Store in secrets manager

**Impact of rotation:**
- Old audit logs cannot correlate with new requests
- Consider before rotating


### PEPPER

**Required:** Yes<br>
**Type:** 64 hexadecimal characters (32 bytes)<br>
**Default:** None<br>

Pepper value for Argon2id password hashing (deletion tokens).

**Generate:**
```bash
openssl rand -hex 32
```

**Example:**
```bash
PEPPER=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

**Purpose:**
- Added to deletion tokens before hashing
- Prevents rainbow table attacks
- Global secret (not per-secret)

**Security:**
- Random generation required
- Never log or expose
- Changing PEPPER invalidates ALL deletion tokens
- Do NOT rotate frequently (breaks existing tokens)


### RATE_LIMIT_RPM

**Required:** No<br>
**Type:** Integer<br>
**Default:** `60`<br>
**Range:** `1-1000`<br>

Rate limit per IP in requests per minute.

**Calculation:** RPM / 60 = requests per second sustained

**Examples:**
```bash
RATE_LIMIT_RPM=60    # 1 req/sec (default)
RATE_LIMIT_RPM=120   # 2 req/sec
RATE_LIMIT_RPM=30    # 0.5 req/sec (strict)
RATE_LIMIT_RPM=300   # 5 req/sec (lenient)
```

**Tuning:**
- Too low: Legitimate users get 429 errors
- Too high: Less protection against abuse
- Monitor logs for 429 errors

**Use cases:**
- Public endpoints: 60-120 RPM
- Internal tools: 300-600 RPM
- High-traffic APIs: 600+ RPM


### RATE_LIMIT_BURST

**Required:** No<br>
**Type:** Integer<br>
**Default:** `10`<br>
**Range:** `1-100`<br>

Burst capacity for rate limiting (token bucket size).

**Examples:**
```bash
RATE_LIMIT_BURST=10   # Allow 10 requests in quick succession
RATE_LIMIT_BURST=20   # Larger bursts
RATE_LIMIT_BURST=5    # Strict (no bursts)
```

**How it works:**
- Client starts with full bucket (BURST tokens)
- Each request consumes 1 token
- Tokens refill at RATE_LIMIT_RPM rate

Example (RPM=60, BURST=10):
- Allows 10 requests instantly
- Then limited to 1 req/sec


### PROXY_MODE

**Required:** No<br>
**Type:** Enum string<br>
**Default:** `Direct`<br>
**Options:** `Direct`, `TrustedProxy`, `Auto`<br>

IP extraction mode for reverse proxy scenarios.

**Modes:**

| Mode | Uses X-Forwarded-For | Validation | Production Safe |
|------|----------------------|------------|----------------|
| Direct | No | N/A |  Yes (no proxy) |
| TrustedProxy | Yes | Validates against TRUSTED_PROXIES |  Yes (with validation) |
| Auto | Yes | None |  NO (spoofable) |

**Examples:**
```bash
# No reverse proxy
PROXY_MODE=Direct

# Behind Caddy/nginx/load balancer
PROXY_MODE=TrustedProxy
TRUSTED_PROXIES=10.0.0.1,10.0.0.2

#  Development only
PROXY_MODE=Auto
```

** Security Warning:**
- **NEVER use `Auto` in production**
- Attackers can spoof X-Forwarded-For headers
- Use `TrustedProxy` with `TRUSTED_PROXIES` validation


### TRUSTED_PROXIES

**Required:** If `PROXY_MODE=TrustedProxy`<br>
**Type:** Comma-separated IP/CIDR list<br>
**Default:** None<br>

List of trusted proxy IP addresses.

**Format:**
```
IP,IP,CIDR/mask,...
```

**Examples:**
```bash
# Single proxy
TRUSTED_PROXIES=10.0.0.1

# Multiple proxies
TRUSTED_PROXIES=10.0.0.1,10.0.0.2,10.0.0.3

# CIDR block
TRUSTED_PROXIES=10.0.0.0/8

# Cloud load balancer ranges
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

**How to find proxy IPs:**
```bash
# Check logs for peer connection IPs
journalctl -u fugata | grep "peer_ip"

# For cloud platforms, check documentation:
# - Render.com: 10.0.0.0/8
# - Fly.io: Check fly status
# - AWS ELB: Check VPC IP ranges
```

**Security:**
- Only list IPs you control
- Do NOT use public IP ranges
- Attackers outside this list cannot spoof IPs


### MAX_SECRET_SIZE

**Required:** No<br>
**Type:** Integer (bytes)<br>
**Default:** `10485760` (10 MB)<br>
**Range:** `1024-104857600` (1 KB - 100 MB)<br>

Maximum secret content size in bytes.

**Examples:**
```bash
MAX_SECRET_SIZE=1048576      # 1 MB
MAX_SECRET_SIZE=10485760     # 10 MB (default)
MAX_SECRET_SIZE=104857600    # 100 MB
```

**Memory impact:**
```
Memory usage = MAX_SECRET_SIZE × concurrent_requests
```

**Calculation:**
- 10 MB × 100 concurrent = 1 GB RAM
- 1 MB × 1000 concurrent = 1 GB RAM

**Tuning:**
- Reduce if memory-constrained
- Increase for large file uploads
- Consider your use case (text vs files)


## Performance Tuning

### LRU_CACHE_SIZE

**Required:** No<br>
**Type:** Integer<br>
**Default:** `1000`<br>
**Range:** `100-100000`<br>

Number of decrypted secrets to cache (LRU eviction).

**Examples:**
```bash
LRU_CACHE_SIZE=1000   # Default
LRU_CACHE_SIZE=5000   # More caching
LRU_CACHE_SIZE=100    # Less memory
```

**Memory usage:**
```
Cache memory = LRU_CACHE_SIZE × average_secret_size
```

**When to increase:**
- High read traffic on same secrets
- Lots of non-one-time secrets
- Memory available

**When to decrease:**
- Memory constrained
- Most secrets are one-time (not cached anyway)


### Argon2 Configuration

Controls deletion token hashing performance vs security.

#### ARGON2_TIME

**Required:** No<br>
**Type:** Integer<br>
**Default:** `4`<br>
**Range:** `1-10`<br>

Time cost (iterations) for Argon2id.

**Tuning:**
```bash
ARGON2_TIME=2    # Faster, less secure
ARGON2_TIME=4    # Default (balanced)
ARGON2_TIME=8    # Slower, more secure
```

**Impact:**
- Higher = more CPU time per hash
- Lower = faster but easier to brute force


#### ARGON2_MEMORY

**Required:** No<br>
**Type:** Integer (KB)<br>
**Default:** `65536` (64 MB)<br>
**Range:** `8192-1048576` (8 MB - 1 GB)<br>

Memory cost for Argon2id.

**Examples:**
```bash
ARGON2_MEMORY=19456    # 19 MB (low memory)
ARGON2_MEMORY=65536    # 64 MB (default)
ARGON2_MEMORY=262144   # 256 MB (high security)
```

**Impact:**
- Higher = more memory per hash (harder to parallelize attacks)
- Lower = less memory usage


#### ARGON2_PARALLELISM

**Required:** No<br>
**Type:** Integer<br>
**Default:** `1`<br>
**Range:** `1-16`<br>

Parallelism degree for Argon2id.

**Examples:**
```bash
ARGON2_PARALLELISM=1    # Sequential (default)
ARGON2_PARALLELISM=4    # 4 parallel lanes
```

**Trade-off:**
- Higher = faster hashing (uses more CPU cores)
- Lower = sequential (consistent timing)


### Worker Configuration

#### HASHER_WORKER_COUNT

**Required:** No<br>
**Type:** Integer<br>
**Default:** `4`<br>
**Range:** `1-32`<br>

Number of Argon2id hashing worker threads.

**Tuning:**
```bash
HASHER_WORKER_COUNT=4    # Default (4 cores)
HASHER_WORKER_COUNT=8    # 8-core server
HASHER_WORKER_COUNT=2    # Low-resource server
```

**Formula:** `workers = CPU_cores`


#### HASHER_QUEUE_SIZE

**Required:** No<br>
**Type:** Integer<br>
**Default:** `100`<br>
**Range:** `10-1000`<br>

Hash task queue size.

**Examples:**
```bash
HASHER_QUEUE_SIZE=100    # Default
HASHER_QUEUE_SIZE=500    # High traffic
```

**When to increase:**
- High burst traffic
- Slow Argon2 settings
- Lots of concurrent deletes


## Development vs Production

### Development Configuration

```bash
# .env (development)
DATABASE_URL=sqlite://./fugata.db
KMS_PROVIDER=Local
KMS_LOCAL_KEY=$(openssl rand -base64 32)
IP_HASH_KEY=$(openssl rand -hex 32)
PEPPER=$(openssl rand -hex 32)

ENVIRONMENT=development
RUST_LOG=debug
PORT=8080

RATE_LIMIT_RPM=600
RATE_LIMIT_BURST=50
```

**Features:**
- SQLite (easy setup)
- Local KMS (no external deps)
- Verbose logging
- Lenient rate limits


### Production Configuration

```bash
# .env (production) - USE SECRETS MANAGER
DATABASE_URL=postgresql://fugata:${DB_PASS}@db.internal/fugata?sslmode=require
DB_MAX_CONNECTIONS=50
DB_QUERY_TIMEOUT_SECS=10

KMS_PROVIDER=Vault
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=${VAULT_TOKEN}
VAULT_MOUNT=transit
VAULT_KEY_NAME=fugata-production-kek

IP_HASH_KEY=${IP_HASH_KEY}   # From secrets manager
PEPPER=${PEPPER}              # From secrets manager

ENVIRONMENT=production
RUST_LOG=info
PORT=8080

RATE_LIMIT_RPM=120
RATE_LIMIT_BURST=20

PROXY_MODE=TrustedProxy
TRUSTED_PROXIES=10.0.0.0/8

MAX_SECRET_SIZE=10485760
LRU_CACHE_SIZE=5000

ARGON2_TIME=4
ARGON2_MEMORY=65536
ARGON2_PARALLELISM=1

HASHER_WORKER_COUNT=8
HASHER_QUEUE_SIZE=200

KMS_FAIL_CLOSED=true
```

**Features:**
- PostgreSQL (scalable)
- Vault/AWS KMS (HSM-backed)
- Moderate logging
- Tuned for production traffic
- Secrets from manager (not .env)


## Configuration Examples

### High-Security Setup

```bash
# Maximum security, performance secondary
DATABASE_URL=postgresql://...?sslmode=require
KMS_PROVIDER=Vault  # Or Aws
RATE_LIMIT_RPM=60
RATE_LIMIT_BURST=5
MAX_SECRET_SIZE=1048576  # 1 MB limit
ARGON2_TIME=8
ARGON2_MEMORY=262144  # 256 MB
PROXY_MODE=TrustedProxy
TRUSTED_PROXIES=10.0.0.1  # Single trusted proxy
```


### High-Performance Setup

```bash
# Optimized for speed, security maintained
DATABASE_URL=postgresql://...
DB_MAX_CONNECTIONS=75
KMS_PROVIDER=Local  #  Dev only! Use Vault/AWS in prod
RATE_LIMIT_RPM=600
LRU_CACHE_SIZE=10000
ARGON2_TIME=2
ARGON2_MEMORY=19456  # 19 MB
HASHER_WORKER_COUNT=16
```


### Resource-Constrained Setup

```bash
# Low memory/CPU server
DATABASE_URL=postgresql://...
DB_MAX_CONNECTIONS=10
KMS_PROVIDER=Vault
RATE_LIMIT_RPM=60
LRU_CACHE_SIZE=500
MAX_SECRET_SIZE=1048576  # 1 MB
ARGON2_MEMORY=19456  # 19 MB
HASHER_WORKER_COUNT=2
```


## Troubleshooting Configuration

### Check Current Configuration

```bash
# View loaded environment
cargo run -- printenv  # If you add this feature

# Or check logs on startup
journalctl -u fugata | grep "Configuration loaded"
```

### Common Mistakes

**1. Missing required variables:**
```
Error: Configuration error: DATABASE_URL not set
→ Add DATABASE_URL to .env
```

**2. Invalid DATABASE_URL:**
```
Error: Invalid connection string
→ Check format: postgresql://user:pass@host/db
```

**3. KMS configuration mismatch:**
```
Error: VAULT_ADDR required when KMS_PROVIDER=Vault
→ Set all Vault variables (ADDR, TOKEN, MOUNT, KEY_NAME)
```

**4. Invalid numeric values:**
```
Error: RATE_LIMIT_RPM must be between 1 and 1000
→ Check range constraints
```


## Security Checklist

Before deploying:

- [ ] Generated fresh IP_HASH_KEY (not default)
- [ ] Generated fresh PEPPER (not default)
- [ ] Using PostgreSQL (not SQLite)
- [ ] Using Vault or AWS KMS (not Local)
- [ ] DATABASE_URL uses strong password
- [ ] DATABASE_URL uses SSL (sslmode=require)
- [ ] All secrets in secrets manager (not .env)
- [ ] PROXY_MODE is Direct or TrustedProxy (not Auto)
- [ ] TRUSTED_PROXIES only lists controlled IPs
- [ ] KMS_FAIL_CLOSED=true
- [ ] Rate limits tuned for expected traffic


**For a quick start, see [README.md](https://github.com/hydroxycult/fugata/blob/main/README.md#quick-start). For API usage, see [API.md](api.md).**

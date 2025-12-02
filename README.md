# Fugata

> **Note:** This is a reference implementation / prototype for self-hosting. Use at your own risk. No warranty provided. Perform your own security review before production use.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)]()

**Fugata** is a Rust backend for securely sharing encrypted secrets (passwords, API keys, sensitive text) with self-destruct capabilities (because it's made to be paranoid).

## What This Is

This is a reference implementation for self-hosting. The backend provides a REST API for creating encrypted secrets that automatically expire after a configured duration. Secrets can be configured for one-time access, meaning they self-destruct after being retrieved once. The implementation includes end-to-end encryption using AES-256-GCM, integration with key management systems (Local/Vault/AWS KMS), rate limiting, and comprehensive audit logging.

**Note:** This is not a hosted service. You must deploy and maintain this yourself. This is a prototype and reference implementation, not production-ready software without your own security review.

## Documentation


[API](docs/api.md) | [Architecture](docs/architecture.md) | [Configuration](docs/configuration.md) | [Security](docs/security.md) 


## Quick Start 

### Step 1: Clone Repository

```bash
git clone https://github.com/hydroxycult/fugata.git
cd fugata/backend
```

### Step 2: Choose Database

**Option A: SQLite** (development/testing)

```bash
cp .env.example .env

#Edit .env and set:
# DATABASE_URL=sqlite://fugada.db
```

**Option B: PostgreSQL** (production)

```bash
# Create database
createdb fugata

# Or via psql:
psql -U postgres
CREATE DATABASE fugata;
\q

cp .env.example .env

# Edit .env and set:
# DATABASE_URL=postgresql://username:password@localhost/fugata
```

### Step 3: Generate Secret Keys

```bash
# Generate three 32-byte random keys
openssl rand -hex 32  # Copy for IP_HASH_KEY
openssl rand -hex 32  # Copy for PEPPER
openssl rand -base64 32  # Copy for KMS_LOCAL_KEY

# Add these to your .env file
```

Your `.env` should now have:

```bash
DATABASE_URL=sqlite://fugata.db
IP_HASH_KEY=<first hex value>
PEPPER=<second hex value>
KMS_LOCAL_KEY=<base64 value>
```

### Step 4: Run Database Migrations

```bash
# Install SQLx CLI
cargo install sqlx-cli --no-default-features --features postgres,sqlite

# Run migrations
sqlx migrate run

# Verify tables created
sqlite3 fugata.db ".schema"  # For SQLite
# OR
psql fugata -c "\dt"  # For PostgreSQL
```

### Step 5: Build and Run

```bash
# Build (takes ~2 minutes first time)
cargo build --release

# Run server
cargo run --release

# Server starts on http://localhost:8080
```

### Step 6: Test It Works

In another terminal:

```bash
# Health check
curl http://localhost:8080/healthz
# Should return: {"status":"ok"}

# Create a secret
curl -X POST http://localhost:8080/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "content": "my-super-secret-password",
    "duration": "1h",
    "one_time": true
  }'

# Response:
# {
#   "id": "fug_abc123...",
#   "deletion_token": "tok_xyz789...",
#   "expires_at": "2025-12-01T12:00:00Z"
# }

# Retrieve the secret (replace with your ID)
curl http://localhost:8080/secrets/fug_abc123...

# Should return the content, then delete itself
```

You have a working Fugata server.

## Limitations

Secrets exist briefly in plaintext in memory during encryption and decryption. While they are zeroized after use, a window of exposure exists for memory dump attacks.

There is no built-in key rotation mechanism. Changing the KEK makes all existing secrets unreadable, requiring manual data migration.

SQLite has poor concurrency due to file-level locking and is not recommended for production use. Use PostgreSQL for production deployments.

Audit logs grow indefinitely without automatic rotation. You must implement external log rotation and archival.

Rate limiting is per-IP only. Distributed attackers with many IP addresses can bypass per-IP limits. Consider using a CDN or WAF for additional Layer 7 protection.

## Contributing

Contributions are welcome. Requirements: changes must include tests, maintain security properties, not break API contracts, compile with zero clippy warnings, and be formatted with cargo fmt. For security vulnerabilities, do not open public issues. See docs/security.md for responsible disclosure procedures.

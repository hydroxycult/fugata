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

## Limitations

Secrets exist briefly in plaintext in memory during encryption and decryption. While they are zeroized after use, a window of exposure exists for memory dump attacks.

There is no built-in key rotation mechanism. Changing the KEK makes all existing secrets unreadable, requiring manual data migration.

SQLite has poor concurrency due to file-level locking and is not recommended for production use. Use PostgreSQL for production deployments.

Audit logs grow indefinitely without automatic rotation. You must implement external log rotation and archival.

Rate limiting is per-IP only. Distributed attackers with many IP addresses can bypass per-IP limits. Consider using a CDN or WAF for additional Layer 7 protection.

## Contributing

Contributions are welcome. Requirements: changes must include tests, maintain security properties, not break API contracts, compile with zero clippy warnings, and be formatted with cargo fmt. For security vulnerabilities, do not open public issues. See docs/security.md for responsible disclosure procedures.

# Security Policy

## Reporting Security Vulnerabilities

**Please do not open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in Fugata, please report it privately.
Contact [here](https://discord.com/users/1424341570965999646) or [here](mailto:hydroxycult@gmail.com).
## Include in your report

1. **Description:** Clear explanation of the vulnerability.
2. **Impact:** What an attacker could accomplish.
3. **Steps to reproduce:** Detailed reproduction steps.
4. **Proof of concept:** Code/curl commands if applicable.
5. **Suggested fix:** If you have recommendations.

### What to Expect

**Response timeline:**
- **Initial response:** Within 72 hours
- **Status update:** Within 7 days
- **Fix timeline:** Varies by severity (see below)

**Severity levels:**
- **Critical:** Fix within 7 days
- **High:** Fix within 30 days
- **Medium:** Fix within 90 days
- **Low:** Best effort basis

### Responsible Disclosure

Please allow reasonable time for a fix before public disclosure:
- **Critical/High:** 90 days
- **Medium/Low:** 180 days

I will credit you in the CHANGELOG and release notes (if desired).


## Scope

### In Scope

Security vulnerabilities in:
- Core encryption implementation
- KMS integration (Vault/AWS)
- Authentication/authorization bypass
- Rate limiting bypass
- Audit logging bypass
- SQL injection
- Memory safety issues
- Information disclosure
- DOS attacks

### Out of Scope

These are NOT considered security vulnerabilities:
- Issues in dependencies (report to upstream)
- Social engineering
- Physical access to server
- Issues requiring admin-level access to server
- Theoretical attacks without proof of concept
- UI/UX issues
- Performance issues (unless DOS-related)


## Security Best Practices

### For Self-Hosters

**Before deploying:**
1. **Change all default secrets**
   - Generate new IP_HASH_KEY, PEPPER, KMS keys
   - Use cryptographically secure random values

2. **Use PostgreSQL, not SQLite**
   - SQLite is for development only
   - PostgreSQL for production

3. **Use Vault or AWS KMS**
   - Never use Local KMS in production
   - KEK must be in HSM

4. **Enable HTTPS**
   - Use reverse proxy (Caddy/nginx)
   - Enforce TLS 1.2+ only
   - Use strong cipher suites

5. **Configure rate limiting**
   - Tune RATE_LIMIT_RPM for your traffic
   - Monitor for 429 errors

6. **Review audit logs**
   - Set up log aggregation
   - Monitor for anomalies
   - Alert on audit failures

7. **Perform your own security review**
   - This is a reference implementation
   - Review code before deploying
   - Hire security consultant if needed


## Known Security Considerations

### Secrets in Memory

**Issue:** Plaintext secrets exist briefly in memory during encryption/decryption.

**Impact:** Memory dumps could reveal secrets.

**Mitigation:**
- Secrets are zeroized after use
- Window of exposure is minimal (~ms)
- Use full-disk encryption
- Disable swap or use encrypted swap


### No Automatic Key Rotation

**Issue:** Changing KEK makes all secrets unreadable.

**Impact:** Cannot rotate KEK without data migration.

**Mitigation:**
- Plan key rotation carefully
- Implement custom migration script
- Consider KEK versioning


### Audit Log Growth

**Issue:** No automatic log rotation/archival.

**Impact:** Disk space exhaustion over time.

**Mitigation:**
- Monitor disk usage
- Set up log rotation (logrotate)
- Archive old logs periodically


### Rate Limiting Bypass

**Issue:** Distributed IPs can bypass per-IP limits.

**Impact:** Coordinated DOS attacks possible.

**Mitigation:**
- Use CDN/WAF for Layer 7 protection
- Monitor aggregate traffic
- Add global rate limits if needed


### SQLite Limitations

**Issue:** File-level locking, poor concurrency.

**Impact:** Performance degradation under load.

**Mitigation:**
- **Do not use SQLite in production**
- Use PostgreSQL for production deployments


## Security Features

### What Fugata Does

 **End-to-end encryption** (AES-256-GCM)
 **Key management** (DEK/KEK model)
 **Authentication** (deletion tokens)
 **Audit logging** (fail-closed)
 **IP privacy** (hashed, not stored)
 **Rate limiting** (per-IP, token bucket)
 **Input validation** (size limits, type checking)
 **SQL injection prevention** (prepared statements)
 **Replay protection** (deletion tokens)
 **Memory safety** (Rust compiler guarantees)


### What Fugata Does NOT Do

 **User authentication** (no login/passwords)
 **Access controls** (anyone with link can access)
 **Multi-factor auth** (not applicable)
 **Web application firewall** (use external WAF)
 **DDoS protection** (use CDN/infrastructure)
 **Automatic key rotation** (manual process required)
 **Encrypted backups** (database backups are your responsibility)
 **Compliance certification** (HIPAA, PCI-DSS, etc.)


## Threat Model

### Assumptions

**I assume:**
- KEK is secure (KMS not compromised)
- Server is not compromised
- TLS is properly configured
- Database access is restricted
- Environment variables are protected
- Admin follows security best practices

**I protect against:**
- Unauthorized secret access (encryption)
- Brute force (rate limiting)
- Replay attacks (one-time tokens)
- SQL injection (prepared statements)
- Memory exhaustion (size limits)
- Information leakage (IP hashing)

**I do not protect against:**
- Compromised KEK (game over)
- Direct database access by attacker
- Memory dumps (secrets briefly in RAM)
- Malicious administrators
- Physical access to server
- Side-channel attacks


## Incident Response

If a vulnerability is discovered and exploited:

1. **Assess impact:**
   - How many secrets affected?
   - Was KEK compromised?
   - Are audit logs intact?

2. **Contain:**
   - Rotate secrets immediately
   - Revoke compromised tokens
   - Block attacker IPs

3. **Remediate:**
   - Apply security patch
   - Review audit logs
   - Verify fix effectiveness

4. **Notify:**
   - Inform affected users (if applicable)
   - Publish security advisory
   - Update documentation

5. **Post-mortem:**
   - Root cause analysis
   - Improve security measures
   - Update threat model


## Security Audit History

**No formal audits have been performed.**<br>
This is a reference implementation / prototype.<br>
**Perform your own security review before production use.**

## Reporting Security Vulnerabilities

**Please do not open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in Fugata, please report it privately.

## **Include in your report:**
1. **Description:** Clear explanation of the vulnerability.
2. **Impact:** What an attacker could accomplish.
3. **Steps to reproduce:** Detailed reproduction steps.
4. **Proof of concept:** Code/curl commands if applicable.
5. **Suggested fix:** If you have recommendations.

### What to Expect

**Response timeline:**
- **Initial response:** Within 72 hours
- **Status update:** Within 7 days
- **Fix timeline:** Varies by severity (see below)

**Severity levels:**
- **Critical:** Fix within 7 days
- **High:** Fix within 30 days
- **Medium:** Fix within 90 days
- **Low:** Best effort basis

### Responsible Disclosure

Please allow reasonable time for a fix before public disclosure:
- **Critical/High:** 90 days
- **Medium/Low:** 180 days

I will credit you in the CHANGELOG and release notes (if desired).


## Scope

### In Scope

Security vulnerabilities in:
- Core encryption implementation
- KMS integration (Vault/AWS)
- Authentication/authorization bypass
- Rate limiting bypass
- Audit logging bypass
- SQL injection
- Memory safety issues
- Information disclosure
- DOS attacks

### Out of Scope

These are NOT considered security vulnerabilities:
- Issues in dependencies (report to upstream)
- Social engineering
- Physical access to server
- Issues requiring admin-level access to server
- Theoretical attacks without proof of concept
- UI/UX issues
- Performance issues (unless DOS-related)


## Security Best Practices

### For Self-Hosters

**Before deploying:**
1. **Change all default secrets**
   - Generate new IP_HASH_KEY, PEPPER, KMS keys
   - Use cryptographically secure random values

2. **Use PostgreSQL, not SQLite**
   - SQLite is for development only
   - PostgreSQL for production

3. **Use Vault or AWS KMS**
   - Never use Local KMS in production
   - KEK must be in HSM

4. **Enable HTTPS**
   - Use reverse proxy (Caddy/nginx)
   - Enforce TLS 1.2+ only
   - Use strong cipher suites

5. **Configure rate limiting**
   - Tune RATE_LIMIT_RPM for your traffic
   - Monitor for 429 errors

6. **Review audit logs**
   - Set up log aggregation
   - Monitor for anomalies
   - Alert on audit failures

7. **Perform your own security review**
   - This is a reference implementation
   - Review code before deploying
   - Hire security consultant if needed


## Known Security Considerations

### Secrets in Memory

**Issue:** Plaintext secrets exist briefly in memory during encryption/decryption.

**Impact:** Memory dumps could reveal secrets.

**Mitigation:**
- Secrets are zeroized after use
- Window of exposure is minimal (~ms)
- Use full-disk encryption
- Disable swap or use encrypted swap


### No Automatic Key Rotation

**Issue:** Changing KEK makes all secrets unreadable.

**Impact:** Cannot rotate KEK without data migration.

**Mitigation:**
- Plan key rotation carefully
- Implement custom migration script
- Consider KEK versioning


### Audit Log Growth

**Issue:** No automatic log rotation/archival.

**Impact:** Disk space exhaustion over time.

**Mitigation:**
- Monitor disk usage
- Set up log rotation (logrotate)
- Archive old logs periodically


### Rate Limiting Bypass

**Issue:** Distributed IPs can bypass per-IP limits.

**Impact:** Coordinated DOS attacks possible.

**Mitigation:**
- Use CDN/WAF for Layer 7 protection
- Monitor aggregate traffic
- Add global rate limits if needed


### SQLite Limitations

**Issue:** File-level locking, poor concurrency.

**Impact:** Performance degradation under load.

**Mitigation:**
- **Do not use SQLite in production**
- Use PostgreSQL for production deployments


## Security Features

### What Fugata Does

 **End-to-end encryption** (AES-256-GCM)
 **Key management** (DEK/KEK model)
 **Authentication** (deletion tokens)
 **Audit logging** (fail-closed)
 **IP privacy** (hashed, not stored)
 **Rate limiting** (per-IP, token bucket)
 **Input validation** (size limits, type checking)
 **SQL injection prevention** (prepared statements)
 **Replay protection** (deletion tokens)
 **Memory safety** (Rust compiler guarantees)


### What Fugata Does NOT Do

 **User authentication** (no login/passwords)
 **Access controls** (anyone with link can access)
 **Multi-factor auth** (not applicable)
 **Web application firewall** (use external WAF)
 **DDoS protection** (use CDN/infrastructure)
 **Automatic key rotation** (manual process required)
 **Encrypted backups** (database backups are your responsibility)
 **Compliance certification** (HIPAA, PCI-DSS, etc.)


## Threat Model

### Assumptions

**I assume:**
- KEK is secure (KMS not compromised)
- Server is not compromised
- TLS is properly configured
- Database access is restricted
- Environment variables are protected
- Admin follows security best practices

**I protect against:**
- Unauthorized secret access (encryption)
- Brute force (rate limiting)
- Replay attacks (one-time tokens)
- SQL injection (prepared statements)
- Memory exhaustion (size limits)
- Information leakage (IP hashing)

**I do not protect against:**
- Compromised KEK (game over)
- Direct database access by attacker
- Memory dumps (secrets briefly in RAM)
- Malicious administrators
- Physical access to server
- Side-channel attacks


## Incident Response

If a vulnerability is discovered and exploited:

1. **Assess impact:**
   - How many secrets affected?
   - Was KEK compromised?
   - Are audit logs intact?

2. **Contain:**
   - Rotate secrets immediately
   - Revoke compromised tokens
   - Block attacker IPs

3. **Remediate:**
   - Apply security patch
   - Review audit logs
   - Verify fix effectiveness

4. **Notify:**
   - Inform affected users (if applicable)
   - Publish security advisory
   - Update documentation

5. **Post-mortem:**
   - Root cause analysis
   - Improve security measures
   - Update threat model


## Security Audit History

**No formal audits have been performed.**<br>
This is a reference implementation / prototype.<br>
**Perform your own security review before production use.**


## Acknowledgments

Security researchers who responsibly disclose vulnerabilities will be credited here (with permission). <br>
**Remember: You are responsible for your own deployment's security.**<br>
**General questions:** GitHub Issues (for non-security topics only)


## Acknowledgments

Security researchers who responsibly disclose vulnerabilities will be credited here (with permission).<br>
**Remember: You are responsible for your own deployment's security.**

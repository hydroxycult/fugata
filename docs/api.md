# Fugata API Reference

Complete REST API documentation with examples in multiple languages.

## Base URL

```
http://localhost:8080
```

**Production:** Replace with your domain (e.g., `https://secrets.example.com`)


## Authentication

**None required** for creating and viewing secrets.

**Bearer token required** for deleting secrets (provided at creation).


## Endpoints

- [Create Secret](#create-secret) - `POST /secrets`
- [Retrieve Secret](#retrieve-secret) - `GET /secrets/{id}`
- [Delete Secret](#delete-secret) - `DELETE /secrets/{id}`
- [Health Check](#health-check) - `GET /healthz`


## Create Secret

Create an encrypted secret with automatic expiry.

### Request

`POST /secrets`

**Headers:**
```
Content-Type: application/json
```

**Body:**
```json
{
  "content": "string",
  "duration": "string",
  "one_time": boolean,
  "metadata": "string" (optional)
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-----------|
| `content` | string | Yes | Secret content (max `MAX_SECRET_SIZE`) |
| `duration` | string | Yes | TTL (must match `TTL_PRESETS`) |
| `one_time` | boolean | No | Delete after first view (default: `false`) |
| `metadata` | string | No | User label (not encrypted) |

**Duration values:**
- `5m` - 5 minutes
- `1h` - 1 hour
- `24h` - 24 hours
- `7d` - 7 days
- `30d` - 30 days

(Configurable via `TTL_PRESETS`)

### Response

**201 Created**

```json
{
  "id": "fug_7x9k2m4n6p8q",
  "deletion_token": "tok_a1b2c3d4e5f6g7h8",
  "expires_at": "2025-12-01T13:30:00Z"
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Secret identifier (shareable) |
| `deletion_token` | string | Token for manual deletion (**SAVE THIS**) |
| `expires_at` | string | ISO 8601 timestamp of expiry |

### Error Responses

**400 Bad Request** - Invalid input
```json
{
  "error": "Invalid duration: must be one of 5m, 1h, 24h, 7d, 30d"
}
```

**413 Payload Too Large** - Content exceeds `MAX_SECRET_SIZE`
```json
{
  "error": "Secret exceeds maximum size of 10485760 bytes"
}
```

**429 Too Many Requests** - Rate limit exceeded
```json
{
  "error": "Rate limit exceeded"
}
```

**500 Internal Server Error** - Server/KMS failure
```json
{
  "error": "Failed to encrypt secret"
}
```

### Examples

#### curl

```bash
curl -X POST http://localhost:8080/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "content": "my-super-secret-password",
    "duration": "1h",
    "one_time": true,
    "metadata": "Production database password"
  }'
```

**Response:**
```json
{
  "id": "fug_abc123def456",
  "deletion_token": "tok_xyz789uvw012",
  "expires_at": "2025-12-01T14:30:00Z"
}
```

#### Python

```python
import requests

response = requests.post('http://localhost:8080/secrets', json={
    'content': 'my-api-key-12345',
    'duration': '24h',
    'one_time': True,
    'metadata': 'Stripe API key'
})

if response.status_code == 201:
    data = response.json()
    print(f"Secret ID: {data['id']}")
    print(f"Deletion token: {data['deletion_token']}")
    print(f"Share: http://localhost:8080/secrets/{data['id']}")
else:
    print(f"Error: {response.status_code} - {response.text}")
```

#### JavaScript

```javascript
const response = await fetch('http://localhost:8080/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        content: 'super-secret-token',
        duration: '7d',
        one_time: false,
        metadata: 'GitHub PAT'
    })
});

if (response.ok) {
    const data = await response.json();
    console.log(`Secret ID: ${data.id}`);
    console.log(`Deletion token: ${data.deletion_token}`);
} else {
    console.error(`Error: ${response.status} - ${await response.text()}`);
}
```

#### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type CreateRequest struct {
    Content  string `json:"content"`
    Duration string `json:"duration"`
    OneTime  bool   `json:"one_time"`
    Metadata string `json:"metadata,omitempty"`
}

type CreateResponse struct {
    ID            string `json:"id"`
    DeletionToken string `json:"deletion_token"`
    ExpiresAt     string `json:"expires_at"`
}

func main() {
    req := CreateRequest{
        Content:  "my-secret",
        Duration: "1h",
        OneTime:  true,
    }

    body, _ := json.Marshal(req)
    resp, err := http.Post(
        "http://localhost:8080/secrets",
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    var result CreateResponse
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("Secret ID: %s\n", result.ID)
}
```


## Retrieve Secret

Retrieve secret content. If `one_time=true`, secret is **permanently deleted** after retrieval.

### Request

`GET /secrets/{id}`

**Parameters:**

| Parameter | Type | Location | Description |
|-----------|------|----------|-------------|
| `id` | string | path | Secret identifier |

**No request body**

### Response

**200 OK**

```json
{
  "content": "my-super-secret-password",
  "metadata": "Production database password",
  "expires_at": "2025-12-01T13:30:00Z",
  "one_time": true
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `content` | string | Decrypted secret content |
| `metadata` | string | User label (null if not set) |
| `expires_at` | string | ISO 8601 timestamp |
| `one_time` | boolean | Was this a one-time secret? |

### Error Responses

**404 Not Found** - Secret doesn't exist, expired, or already viewed (one-time)
```json
{
  "error": "Secret not found"
}
```

**429 Too Many Requests**
```json
{
  "error": "Rate limit exceeded"
}
```

**500 Internal Server Error** - KMS/decryption failure
```json
{
  "error": "Failed to decrypt secret"
}
```

### Examples

#### curl

```bash
curl http://localhost:8080/secrets/fug_abc123def456
```

**Response:**
```json
{
  "content": "my-super-secret-password",
  "metadata": "Production database password",
  "expires_at": "2025-12-01T14:30:00Z",
  "one_time": true
}
```

**Second request (one-time secret):**
```bash
curl http://localhost:8080/secrets/fug_abc123def456
```

**Response:**
```json
{
  "error": "Secret not found"
}
```

#### Python

```python
import requests

response = requests.get(f'http://localhost:8080/secrets/{secret_id}')

if response.status_code == 200:
    data = response.json()
    print(f"Secret: {data['content']}")
    print(f"Metadata: {data['metadata']}")
    if data['one_time']:
        print("  This secret has been permanently deleted")
elif response.status_code == 404:
    print("Secret not found (expired or already viewed)")
else:
    print(f"Error: {response.status_code}")
```

#### JavaScript

```javascript
const response = await fetch(`http://localhost:8080/secrets/${secretId}`);

if (response.ok) {
    const data = await response.json();
    console.log(`Secret: ${data.content}`);
    if (data.one_time) {
        console.warn('This secret has been destroyed');
    }
} else if (response.status === 404) {
    console.error('Secret not found');
} else {
    console.error(`Error: ${response.status}`);
}
```

#### Go

```go
type GetResponse struct {
    Content   string `json:"content"`
    Metadata  string `json:"metadata"`
    ExpiresAt string `json:"expires_at"`
    OneTime   bool   `json:"one_time"`
}

func getSecret(id string) (*GetResponse, error) {
    resp, err := http.Get(fmt.Sprintf("http://localhost:8080/secrets/%s", id))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("status %d", resp.StatusCode)
    }

    var result GetResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}
```


## Delete Secret

Manually delete a secret before expiry.

### Request

`DELETE /secrets/{id}`

**Headers:**
```
Authorization: Bearer {deletion_token}
```

**Parameters:**

| Parameter | Type | Location | Description |
|-----------|------|----------|-------------|
| `id` | string | path | Secret identifier |
| `deletion_token` | string | header | Token from create response |

**No request body**

### Response

**200 OK**

```json
{
  "message": "Secret deleted successfully"
}
```

### Error Responses

**401 Unauthorized** - Missing or invalid deletion token
```json
{
  "error": "Unauthorized"
}
```

**404 Not Found** - Secret doesn't exist or already deleted
```json
{
  "error": "Secret not found"
}
```

**429 Too Many Requests**
```json
{
  "error": "Rate limit exceeded"
}
```

### Examples

#### curl

```bash
curl -X DELETE http://localhost:8080/secrets/fug_abc123def456 \
  -H "Authorization: Bearer tok_xyz789uvw012"
```

**Response:**
```json
{
  "message": "Secret deleted successfully"
}
```

#### Python

```python
import requests

response = requests.delete(
    f'http://localhost:8080/secrets/{secret_id}',
    headers={'Authorization': f'Bearer {deletion_token}'}
)

if response.status_code == 200:
    print("Secret deleted successfully")
elif response.status_code == 401:
    print("Invalid deletion token")
elif response.status_code == 404:
    print("Secret not found")
else:
    print(f"Error: {response.status_code}")
```

#### JavaScript

```javascript
const response = await fetch(`http://localhost:8080/secrets/${secretId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${deletionToken}` }
});

if (response.ok) {
    console.log('Secret deleted successfully');
} else if (response.status === 401) {
    console.error('Invalid deletion token');
}else if (response.status === 404) {
    console.error('Secret not found');
}
```

#### Go

```go
func deleteSecret(id, token string) error {
    req, _ := http.NewRequest(
        "DELETE",
        fmt.Sprintf("http://localhost:8080/secrets/%s", id),
        nil,
    )
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("status %d", resp.StatusCode)
    }
    return nil
}
```


## Health Check

Check if server is running and database is accessible.

### Request

`GET /healthz`

**No parameters or body**

### Response

**200 OK** - Service healthy

```json
{
  "status": "ok"
}
```

**503 Service Unavailable** - Service unhealthy

```json
{
  "status": "unhealthy",
  "error": "Database connection failed"
}
```

### Examples

#### curl

```bash
curl http://localhost:8080/healthz
```

**For monitoring/alerting:**
```bash
curl -f http://localhost:8080/healthz || echo "Service down!"
```

#### Python

```python
import requests

try:
    response = requests.get('http://localhost:8080/healthz', timeout=5)
    if response.status_code == 200:
        print(" Service healthy")
    else:
        print(f" Service unhealthy: {response.status_code}")
except requests.RequestException as e:
    print(f" Service unreachable: {e}")
```

#### Kubernetes Probe

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
  periodSeconds: 10
```


## Rate Limiting

All endpoints are rate-limited per IP address.

### Headers

Rate limit information included in response headers:

```
X-RateLimit-Limit: 60      # Requests per minute
X-RateLimit-Remaining: 45  # Remaining requests
X-RateLimit-Reset: 1638360000  # Unix timestamp
```

### Behavior

**Algorithm:** Token bucket

**Configuration:**
- `RATE_LIMIT_RPM`: Sustained rate (requests/minute)
- `RATE_LIMIT_BURST`: Burst capacity (max tokens)

**Example (RPM=60, BURST=10):**
- Start with 10 tokens
- Each request consumes 1 token
- Tokens refill at 1/second
- Burst of 10 requests allowed
- Then limited to 1 req/sec

### When Limited

**Response:**
```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1638360120

{
  "error": "Rate limit exceeded"
}
```

**Retry after:** Check `X-RateLimit-Reset` header


## Error Responses

### Standard Error Format

```json
{
  "error": "Human-readable error message"
}
```

### HTTP Status Codes

| Status | Meaning | Common Causes |
|--------|---------|---------------|
| 200 | OK | Success |
| 201 | Created | Secret created |
| 400 | Bad Request | Invalid input (duration, content size) |
| 401 | Unauthorized | Invalid deletion token |
| 404 | Not Found | Secret doesn't exist or expired |
| 413 | Payload Too Large | Content > MAX_SECRET_SIZE |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server/KMS failure |
| 503 | Service Unavailable | Database/KMS unavailable |


## Client Libraries

### Official

No official client libraries yet. Contributions welcome!

### Community

- **Python:** See `examples/clients/python_example.py`
- **JavaScript:** See `examples/clients/javascript_example.js`
- **Bash:** See `examples/clients/curl_example.sh`

### Creating a Client

**Minimum requirements:**
1. `POST /secrets` - Create secret
2. `GET /secrets/{id}` - Retrieve secret
3. `DELETE /secrets/{id}` - Delete secret (with Authorization header)
4. Handle rate limiting (respect 429 responses)
5. Handle errors gracefully

**Best practices:**
- Use HTTPS in production
- Never log secret content
- Validate server TLS certificate
- Implement exponential backoff for retries
- Respect rate limit headers


## Security Considerations

### HTTPS Required

**WARNING:** Always use HTTPS in production.

HTTP transmits secrets in plaintext over the network.

```python
#  BAD (production)
response = requests.post('http://secrets.example.com/secrets', ...)

#  GOOD (production)
response = requests.post('https://secrets.example.com/secrets', ...)
```

### Deletion Tokens

**Save deletion tokens!**

```python
# When creating secret
result = create_secret(content)
deletion_token = result['deletion_token']

# Store token securely (don't print/log)
# Use for deletion later
delete_secret(result['id'], deletion_token)
```

### One-Time Secrets

**Be careful with one-time secrets:**

```python
# First view destroys the secret
secret = get_secret(secret_id)
print(secret['content'])

# Second view fails (404)
secret = get_secret(secret_id)  # Error: not found
```

### Rate Limiting

**Implement backoff:**

```python
import time

for attempt in range(3):
    response = requests.post(...)
    if response.status_code == 429:
        # Wait and retry
        time.sleep(2 ** attempt)
        continue
    break
```


## API Versioning

**Current version:** v1 (implicit)

**Breaking changes:**
- Will increment version (e.g., `/v2/secrets`)
- v1 will remain available for compatibility
- Deprecation notice: 6 months minimum



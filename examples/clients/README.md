# Client Examples

This directory contains example API usage in different languages.

## Examples

- **`curl_example.sh`** - Bash/curl for command-line usage
- **`python_example.py`** - Python 3 with requests library
- **`javascript_example.js`** - Node.js/JavaScript with fetch API

## Usage

### Bash/curl

```bash
chmod +x curl_example.sh
export API_URL=http://localhost:8080
./curl_example.sh
```

Requirements: `curl`, `jq`

### Python

```bash
python3 python_example.py
```

Requirements: `requests` library (`pip install requests`)

### JavaScript

```bash
node javascript_example.js
```

Requirements: Node.js 18+ (for built-in fetch)

## API Endpoints

All examples demonstrate:

1. **Create Secret** - `POST /secrets`
2. **Get Secret** - `GET /secrets/{id}`
3. **Verify Destruction** - GET again (should fail for one-time secrets)

Optional:
- **Delete Secret** - `DELETE /secrets/{id}` with Authorization header
- **Health Check** - `GET /healthz`

See the main README for complete API documentation.

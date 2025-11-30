#!/bin/bash
# Example: Create and retrieve a secret using curl

API_URL="${API_URL:-http://localhost:8080}"

echo "==> Creating secret..."
RESPONSE=$(curl -s -X POST "$API_URL/secrets" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "my-super-secret-password",
    "duration": "1h",
    "one_time": true,
    "metadata": "Production database password"
  }')
echo "$RESPONSE" | jq .
SECRET_ID=$(echo "$RESPONSE" | jq -r '.id')
DELETION_TOKEN=$(echo "$RESPONSE" | jq -r '.deletion_token')
echo ""
echo "==> Secret created!"
echo "Secret ID: $SECRET_ID"
echo "Deletion Token: $DELETION_TOKEN"
echo "Share this URL: $API_URL/secrets/$SECRET_ID"
echo ""
echo "==> Retrieving secret..."
curl -s "$API_URL/secrets/$SECRET_ID" | jq .
echo ""
echo "==> Trying to retrieve again (should fail - one-time secret)..."
curl -s "$API_URL/secrets/$SECRET_ID" | jq .

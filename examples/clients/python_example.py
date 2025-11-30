#!/usr/bin/env python3
"""
Python client example for Fugata API
"""

import requests
import sys
import json

API_URL = "http://localhost:8080"

def create_secret(content, duration="1h", one_time=True, metadata=None):
    """Create a new secret"""
    response = requests.post(
        f"{API_URL}/secrets",
        json={
            "content": content,
            "duration": duration,
            "one_time": one_time,
            "metadata": metadata
        }
    )
    response.raise_for_status()
    return response.json()

def get_secret(secret_id):
    """Retrieve a secret (destroys it if one-time)"""
    response = requests.get(f"{API_URL}/secrets/{secret_id}")
    response.raise_for_status()
    return response.json()

def delete_secret(secret_id, deletion_token):
    """Manually delete a secret"""
    response = requests.delete(
        f"{API_URL}/secrets/{secret_id}",
        headers={"Authorization": f"Bearer {deletion_token}"}
    )
    response.raise_for_status()
    return response.json()

def health_check():
    """Check API health"""
    response = requests.get(f"{API_URL}/healthz")
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    print("==> Creating secret...")
    result = create_secret(
        content="my-super-secret-password",
        duration="1h",
        one_time=True,
        metadata="Production database password"
    )
    
    print(json.dumps(result, indent=2))
    secret_id = result["id"]
    deletion_token = result["deletion_token"]
    
    print(f"\n==> Secret created!")
    print(f"Secret ID: {secret_id}")
    print(f"Deletion Token: {deletion_token}")
    print(f"Share this URL: {API_URL}/secrets/{secret_id}")
    
    print(f"\n==> Retrieving secret...")
    secret = get_secret(secret_id)
    print(json.dumps(secret, indent=2))
    
    print(f"\n==> Trying to retrieve again (should fail - one-time)...")
    try:
        secret = get_secret(secret_id)
        print("ERROR: Secret should have been destroyed!")
    except requests.HTTPError as e:
        print(f"✓ Correctly failed with: {e.response.status_code} {e.response.text}")

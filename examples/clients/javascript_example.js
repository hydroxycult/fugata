// JavaScript/Node.js client example for Fugata API

const API_URL = process.env.API_URL || 'http://localhost:8080';

async function createSecret(content, duration = '1h', oneTime = true, metadata = null) {
    const response = await fetch(`${API_URL}/secrets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            content,
            duration,
            one_time: oneTime,
            metadata
        })
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }

    return await response.json();
}

async function getSecret(secretId) {
    const response = await fetch(`${API_URL}/secrets/${secretId}`);

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }

    return await response.json();
}

async function deleteSecret(secretId, deletionToken) {
    const response = await fetch(`${API_URL}/secrets/${secretId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${deletionToken}` }
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }

    return await response.json();
}

async function healthCheck() {
    const response = await fetch(`${API_URL}/healthz`);
    return await response.json();
}

async function main() {
    console.log('==> Creating secret...');
    const result = await createSecret(
        'my-super-secret-password',
        '1h',
        true,
        'Production database password'
    );

    console.log(JSON.stringify(result, null, 2));
    const { id: secretId, deletion_token: deletionToken } = result;

    console.log(`\n==> Secret created!`);
    console.log(`Secret ID: ${secretId}`);
    console.log(`Deletion Token: ${deletionToken}`);
    console.log(`Share this URL: ${API_URL}/secrets/${secretId}`);

    console.log(`\n==> Retrieving secret...`);
    const secret = await getSecret(secretId);
    console.log(JSON.stringify(secret, null, 2));

    console.log(`\n==> Trying to retrieve again (should fail - one-time)...`);
    try {
        await getSecret(secretId);
        console.log('ERROR: Secret should have been destroyed!');
    } catch (error) {
        console.log(`✓ Correctly failed with: ${error.message}`);
    }
}

main().catch(console.error);

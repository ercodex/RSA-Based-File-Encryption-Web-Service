import pytest
import time
from fastapi.testclient import TestClient
from main import app, API_KEY

client = TestClient(app)

# --- 1. FUNCTIONAL TESTS ---

def test_health_check():
    """Service status test"""
    response = client.get("/")
    assert response.status_code == 200
    assert "RSA-2048" in response.json()["algorithm"]

def test_encryption_decryption_cycle():
    """Tests the full lifecycle and integrity of data"""
    headers = {"X-API-KEY": API_KEY}
    secret_msg = "Top secret message 123!".encode('utf-8')
    
    # Encrypt
    files = {'file': ('doc.txt', secret_msg)}
    enc_res = client.post("/encrypt", headers=headers, files=files)
    assert enc_res.status_code == 200
    
    # Integrity Check: Compare Hash (Question 1a)
    returned_hash = enc_res.headers.get("X-File-Integrity")
    assert returned_hash is not None
    
    # Decrypt
    dec_res = client.post("/decrypt", headers=headers, files={'file': ('enc.txt', enc_res.content)})
    assert dec_res.status_code == 200
    assert dec_res.json()["decrypted_content"] == secret_msg.decode('utf-8')

# --- 2. SECURITY & BOUNDARY TESTS ---

def test_unauthorized_access():
    """Security check for invalid API keys"""
    response = client.post("/encrypt", headers={"X-API-KEY": "hacker-key"})
    assert response.status_code == 403

def test_invalid_file_extension():
    """Input validation for disallowed file types"""
    headers = {"X-API-KEY": API_KEY}
    files = {'file': ('malicious.exe', b'print("hello")')}
    response = client.post("/encrypt", headers=headers, files=files)
    assert response.status_code == 400
    assert "Disallowed file extension" in response.json()["detail"]

def test_file_size_overflow():
    """Testing the 190-byte RSA physical limit"""
    headers = {"X-API-KEY": API_KEY}
    oversized_data = b"A" * 200
    files = {'file': ('big.txt', oversized_data)}
    response = client.post("/encrypt", headers=headers, files=files)
    assert response.status_code == 400
    assert "File size exceeds" in response.json()["detail"]

# --- 3. OPERATIONAL SECURITY TESTS ---

def test_rate_limiting():
    """Testing Denial of Service protection"""
    headers = {"X-API-KEY": API_KEY}
    # Send multiple requests quickly to trigger 429
    for _ in range(5):
        response = client.get("/", headers=headers)
        if response.status_code == 429:
            break
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]

def test_decryption_failure_handling():
    """Fail-secure behavior on corrupted data"""
    headers = {"X-API-KEY": API_KEY}
    bad_data = b"not-encrypted-properly"
    response = client.post("/decrypt", headers=headers, files={'file': ('bad.txt', bad_data)})
    assert response.status_code == 400
    assert "Decryption failed" in response.json()["detail"]
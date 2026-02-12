import pytest
import os
from fastapi.testclient import TestClient
from main import app, API_KEY

client = TestClient(app)

def test_health_check():
    """Does service works?"""
    response = client.get("/")
    assert response.status_code == 200

def test_unauthorized_access():
    """Wrong API key test"""
    response = client.post("/encrypt", headers={"X-API-KEY": "wrong-key"})
    assert response.status_code == 403

def test_full_crypto_flow():
    """Does encrypt-decrypt loop works correct?"""
    headers = {"X-API-KEY": API_KEY}
    original_data = "I love barbecue.".encode('utf-8')
    
    # Load the file
    files = {'file': ('test.txt', original_data)}
    encrypt_res = client.post("/encrypt", headers=headers, files=files)
    assert encrypt_res.status_code == 200
    
    # Get encrypted content
    encrypted_content = encrypt_res.content
    
    # Send it to decrypt
    decrypt_res = client.post("/decrypt", headers=headers, files={'file': ('enc_test.txt', encrypted_content)})
    assert decrypt_res.status_code == 200
    assert decrypt_res.json()["decrypted_data"] == original_data.decode('utf-8')

def test_file_size_limit():
    """Does it gives an error about file size limit exceedings?"""
    headers = {"X-API-KEY": API_KEY}
    large_data = b"A" * 300 # Bigger than 190 byte
    files = {'file': ('large.txt', large_data)}
    
    response = client.post("/encrypt", headers=headers, files=files)
    assert response.status_code == 400
    assert "File too large" in response.json()["detail"]
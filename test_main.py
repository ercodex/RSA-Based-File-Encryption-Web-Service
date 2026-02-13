import pytest
import time
from fastapi.testclient import TestClient
from main import app, TENANT_DB # Now we get keys from TENANT_DB

# raise_server_exceptions=False: We can bypass errors in the code to keep the test running
client = TestClient(app, raise_server_exceptions=True)

# We get a valid key and expected ID from TENANT_DB
VALID_API_KEY = list(TENANT_DB.keys())[0]
EXPECTED_TENANT_ID = TENANT_DB[VALID_API_KEY]["id"]

@pytest.fixture(autouse=True)
def slow_down_tests():
    """We wait 1.1 seconds after each test to clean Rate Limiter"""
    yield
    time.sleep(1.1)

# 1. Health Check
def test_health_check():
    response = client.get("/")
    assert response.status_code == 200

# 2. Unauthorized Access (Security Test: Negative Testing)
def test_unauthorized_access():
    headers = {"X-API-KEY": "wrong-key-456"}
    response = client.post("/encrypt", headers=headers, files={'file': ('test.txt', b'Hello World')})
    # Covers both unauthorized access and rate limit. Checks error message detail
    assert response.status_code in [403, 429]
    if response.status_code == 403:
        assert "Invalid API Key" in response.json()["detail"]

# 3. Full Crypto Cycle & Tenant Validation (Security Test: Multi-tenancy)
def test_encryption_decryption_cycle():
    headers = {"X-API-KEY": VALID_API_KEY}
    original_data = b"Secret Project Data"
    
    # --- Encrypt Phase ---
    enc_res = client.post("/encrypt", headers=headers, files={'file': ('data.txt', original_data)})
    assert enc_res.status_code == 200
    # Future work: Tenant isolation control?
    assert enc_res.headers.get("X-Tenant-ID") == EXPECTED_TENANT_ID
    
    ciphertext_hex = enc_res.text
    time.sleep(1.1) 
    
    # --- Decrypt Phase ---
    dec_res = client.post("/decrypt", headers=headers, files={'file': ('enc_data.txt', ciphertext_hex)})
    assert dec_res.status_code == 200
    assert dec_res.json()["decrypted_content"] == original_data.decode()
    # Future work: Tenant context check in response?
    assert "tenant_context" in dec_res.json()

# 4. Invalid File Extension (Input Validation)
def test_invalid_extension():
    headers = {"X-API-KEY": VALID_API_KEY}
    files = {'file': ('malicious.exe', b'malware content')}
    response = client.post("/encrypt", headers=headers, files=files)
    assert response.status_code == 400
    assert "Disallowed file extension" in response.json()["detail"]

# 5. File Size Limit (Security Test: RSA Boundary)
def test_file_size_limit():
    headers = {"X-API-KEY": VALID_API_KEY}
    big_data = b"A" * 250 # Exceeds 190 byte limit
    files = {'file': ('too_big.txt', big_data)}
    response = client.post("/encrypt", headers=headers, files=files)
    # RSA returns 400 to prevent limit errors
    assert response.status_code == 400
    assert "File size exceeds" in response.json()["detail"]

# 6. Rate Limiting (DoS Mitigation)
def test_rate_limiting_trigger():
    headers = {"X-API-KEY": VALID_API_KEY}
    responses = []
    for _ in range(3):
        responses.append(client.get("/", headers=headers).status_code)
    
    assert 429 in responses
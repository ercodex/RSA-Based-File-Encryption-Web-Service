import time
import pytest
from fastapi.testclient import TestClient
from main import app, TENANT_DB

# Standard FastAPI exception handling
client = TestClient(app, raise_server_exceptions=True)

# Test Constants
TENANT_A_KEY = list(TENANT_DB.keys())[0]  # Company_A
TENANT_B_KEY = list(TENANT_DB.keys())[1]  # Company_B
TENANT_A_ID = TENANT_DB[TENANT_A_KEY]["id"]

@pytest.fixture(autouse=True)
def slow_down_tests():
    """Wait 1.1s after each test to reset the Rate Limiter state"""
    yield
    time.sleep(1.1)

# --- PART 1: ATOMIC UNIT TESTS (Smallest logical units) ---

def test_health_check():
    """1. Atomic: Verify the server is responsive"""
    assert client.get("/").status_code == 200

def test_unauthorized_access_atomic():
    """2. Atomic: Verify invalid API keys are rejected"""
    headers = {"X-API-KEY": "wrong-key-456"}
    res = client.post("/encrypt", headers=headers, files={'file': ('a.txt', b'test')})
    assert res.status_code == 403

def test_invalid_extension_atomic():
    """3. Atomic: Verify blocked file extensions (e.g., .exe)"""
    headers = {"X-API-KEY": TENANT_A_KEY}
    res = client.post("/encrypt", headers=headers, files={'file': ('test.exe', b'content')})
    assert res.status_code == 400

def test_file_size_limit_atomic():
    """4. Atomic: Verify the 190-byte RSA capacity limit"""
    headers = {"X-API-KEY": TENANT_A_KEY}
    res = client.post("/encrypt", headers=headers, files={'file': ('big.txt', b'A'*250)})
    assert res.status_code == 400

def test_tenant_header_logic_atomic():
    """5. Atomic: Verify correct Tenant ID is returned in the response header"""
    headers = {"X-API-KEY": TENANT_A_KEY}
    res = client.post("/encrypt", headers=headers, files={'file': ('a.txt', b'data')})
    assert res.headers.get("X-Tenant-ID") == TENANT_A_ID

def test_cryptographic_integrity_atomic():
    """6. Atomic: Verify decrypted data matches the original plaintext"""
    headers = {"X-API-KEY": TENANT_A_KEY}
    original = b"Integrity Check"
    enc_res = client.post("/encrypt", headers=headers, files={'file': ('a.txt', original)})
    ciphertext = enc_res.text
    time.sleep(1.1)
    dec_res = client.post("/decrypt", headers=headers, files={'file': ('b.txt', ciphertext)})
    assert dec_res.json()["decrypted_content"] == original.decode()

def test_rate_limiting_atomic():
    """7. Atomic: Verify the Rate Limiting middleware is triggered"""
    headers = {"X-API-KEY": TENANT_A_KEY}
    responses = [client.get("/", headers=headers).status_code for _ in range(3)]
    assert 429 in responses

# --- PART 2: COMBINED SCENARIO TESTS (System Integration) ---

def test_scenario_full_authorized_workflow():
    """
    8. Scenario: Auth -> Encrypt -> Wait -> Decrypt -> Context check.
    Validates that all components (Auth, Crypto, and Context) function together seamlessly.
    """
    headers = {"X-API-KEY": TENANT_A_KEY}
    data = b"Complete Workflow Test"

    # Step 1: Encryption and Tenant ID validation
    enc_res = client.post("/encrypt", headers=headers, files={'file': ('data.txt', data)})
    assert enc_res.status_code == 200
    assert enc_res.headers.get("X-Tenant-ID") == TENANT_A_ID
    
    ciphertext = enc_res.text
    time.sleep(1.1) 

    # Step 2: Decryption and Context/Integrity validation
    dec_res = client.post("/decrypt", headers=headers, files={'file': ('enc.txt', ciphertext)})
    assert dec_res.json()["decrypted_content"] == data.decode()
    assert dec_res.json()["tenant_context"] == "Company_A"

def test_scenario_authorized_user_abuse_protection():
    """
    9. Scenario: Valid user performs a DoS attempt.
    Tests the interaction between successful Authentication and Rate Limit protection.
    """
    headers = {"X-API-KEY": TENANT_A_KEY}
    # First request should succeed
    assert client.get("/", headers=headers).status_code == 200
    # Immediate second request should be blocked by Rate Limiter
    res = client.get("/", headers=headers)
    assert res.status_code == 429

def test_scenario_multi_tenant_traceability():
    """
    10. Scenario: Operational traceability across different tenants.
    Confirms the system correctly distinguishes between Tenant A and Tenant B.
    """
    # Tenant A Operation
    res_a = client.post("/encrypt", headers={"X-API-KEY": TENANT_A_KEY}, files={'file': ('a.txt', b'data')})
    assert res_a.headers.get("X-Tenant-ID") == "tenant_001"
    
    time.sleep(1.1)

    # Tenant B Operation
    res_b = client.post("/encrypt", headers={"X-API-KEY": TENANT_B_KEY}, files={'file': ('b.txt', b'data')})
    assert res_b.headers.get("X-Tenant-ID") == "tenant_002"
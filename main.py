import os
import logging
import time
from fastapi import FastAPI, UploadFile, File, HTTPException, Security, Request
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import FileResponse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- LOGGING & CONFIG ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecureCryptoService")

app = FastAPI(title="Hardened RSA Encryption Service")

API_KEY = "secure-assignment-key-2025"
api_key_header = APIKeyHeader(name="X-API-KEY")

# Simple In-memory Rate Limiting (Question 2: DoS Mitigation)
request_history = {}

# --- KEY MANAGEMENT (Question 7b & 8a) ---
KEY_FOLDER = "secure_keys"
PRIV_KEY_PATH = os.path.join(KEY_FOLDER, "private_key.pem")

if not os.path.exists(KEY_FOLDER):
    os.makedirs(KEY_FOLDER)

def load_or_generate_keys():
    """Ensures cryptographic agility and persistence"""
    if os.path.exists(PRIV_KEY_PATH):
        with open(PRIV_KEY_PATH, "rb") as k:
            priv = serialization.load_pem_private_key(k.read(), password=None)
            logger.info("Existing RSA keys loaded from disk.")
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PRIV_KEY_PATH, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logger.info("New RSA keys generated and saved to disk.")
    return priv, priv.public_key()

private_key, public_key = load_or_generate_keys()

# --- SECURITY MIDDLEWARE ---
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    now = time.time()
    if client_ip in request_history and now - request_history[client_ip] < 1:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again in 1s.")
    request_history[client_ip] = now
    return await call_next(request)

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        logger.warning(f"Unauthorized access attempt from IP: {api_key}")
        raise HTTPException(status_code=403, detail="Forbidden: Invalid API Key")
    return api_key

# --- ENDPOINTS ---
@app.get("/")
def status():
    return {"status": "Operational", "algorithm": "RSA-2048/OAEP"}

@app.post("/encrypt", dependencies=[Security(get_api_key)])
async def encrypt(file: UploadFile = File(...)):
    # Input Validation (Question 5a)
    if not file.filename.endswith(('.txt', '.pdf', '.docx')):
        raise HTTPException(status_code=400, detail="Disallowed file extension.")

    data = await file.read()
    if len(data) > 190: # RSA physical limit for 2048-bit with OAEP
        raise HTTPException(status_code=400, detail="File size exceeds RSA-2048 block limit.")

    try:
        # Integrity check: Hash before encryption (Question 3b)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        file_hash = digest.finalize().hex()

        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        enc_name = f"enc_{file.filename}"
        with open(enc_name, "wb") as f:
            f.write(ciphertext)

        logger.info(f"File {file.filename} encrypted. Hash: {file_hash}")
        return FileResponse(path=enc_name, filename=enc_name, headers={"X-File-Integrity": file_hash})
    except Exception as e:
        logger.error(f"Internal Crypto Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Encryption failure.")

@app.post("/decrypt", dependencies=[Security(get_api_key)])
async def decrypt(file: UploadFile = File(...)):
    enc_data = await file.read()
    try:
        decrypted = private_key.decrypt(
            enc_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"decrypted_content": decrypted.decode('utf-8')}
    except Exception:
        # Fail-secure: Generic error (Question 3b)
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid data or key.")
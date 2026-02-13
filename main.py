import os
import time
import secrets 
import hashlib
import logging # Yeni ekleme
from datetime import datetime # Yeni ekleme
from typing import Dict
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- Security Logging Configuration ---
# Log formatı SIEM (Security Information and Event Management) sistemlerine uygun hale getirildi.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SecurityAudit")

# --- API Initialization ---
app = FastAPI(
    title="Bespoke RSA Encryption Service",
    description="A secure web service for RSA-2048 encryption.",
    version="1.0.0"
)

# --- Configuration ---
# API_KEY değişkeni TENANT_DB'den kontrol edileceği için burada sabit tutulabilir veya kaldırılabilir.
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

KEY_DIR = "secure_keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")

# Rate limiting storage
request_history: Dict[str, float] = {}

if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)

# --- Multi-Tenant Demo Configuration ---
TENANT_DB = {
    "super-secret-key-123": {"id": "tenant_001", "name": "Company_A"},
    "other-secret-key-456": {"id": "tenant_002", "name": "Company_B"}
}

async def get_api_key(api_key: str = Depends(api_key_header)):
    valid_key_found = False
    current_tenant = None
    
    # Timing attack protection with secrets.compare_digest
    for key, context in TENANT_DB.items():
        if api_key and secrets.compare_digest(api_key, key):
            valid_key_found = True
            current_tenant = context
            break
            
    if not valid_key_found:
        # Başarısız giriş denemesi loglanıyor (Audit Trail)
        logger.warning(f"AUTH_FAILURE | Invalid API Key provided.")
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return current_tenant

# --- Middleware: Rate Limiting ---
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # EXCEPTION: Allow documentation and openapi schema to bypass rate limiting
    # This prevents the UI from breaking due to concurrent browser requests.
    if request.url.path in ["/docs", "/openapi.json", "/redoc"]:
        return await call_next(request)

    client_ip = request.client.host
    now = time.time()
    
    if client_ip in request_history and now - request_history[client_ip] < 1:
        logger.warning(f"RATE_LIMIT_EXCEEDED | IP: {client_ip} | Path: {request.url.path}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again in 1s."}
        )
        
    request_history[client_ip] = now
    return await call_next(request)

# --- Key Management ---
def load_or_generate_keys():
    if os.path.exists(PRIVATE_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        public_key = private_key.public_key()
    else:
        logger.info("KEY_MANAGEMENT | Generating new RSA-2048 key pair.")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return private_key, public_key

private_key, public_key = load_or_generate_keys()

# --- Endpoints ---

@app.get("/")
async def health_check():
    return {"status": "online", "algorithm": "RSA-2048 / OAEP"}

@app.post("/encrypt", tags=["Crypto Operations"])
async def encrypt_file(file: UploadFile = File(...), tenant: dict = Depends(get_api_key)):
    allowed_exts = {".txt", ".pdf", ".docx"}
    _, ext = os.path.splitext(file.filename)
    if ext.lower() not in allowed_exts:
        logger.error(f"VALIDATION_ERROR | Tenant: {tenant['id']} | Invalid extension: {ext}")
        raise HTTPException(status_code=400, detail=f"Disallowed file extension: {ext}")

    content = await file.read()
    
    if len(content) > 190:
        logger.error(f"VALIDATION_ERROR | Tenant: {tenant['id']} | File too large.")
        raise HTTPException(status_code=400, detail="File size exceeds RSA 2048-bit capacity.")

    # --- SECURITY LOGGING ---
    logger.info(f"CRYPTO_ACTION: ENCRYPT | Tenant: {tenant['id']} ({tenant['name']}) | File: {file.filename}")

    ciphertext = public_key.encrypt(
        content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    file_hash = hashlib.sha256(content).hexdigest()
    
    return Response(
        content=ciphertext.hex(), 
        media_type="text/plain",
        headers={
            "X-File-Integrity": file_hash,
            "X-Tenant-ID": tenant['id']
        }
    )

@app.post("/decrypt", tags=["Crypto Operations"])
async def decrypt_file(file: UploadFile = File(...), tenant: dict = Depends(get_api_key)):
    try:
        # --- SECURITY LOGGING ---
        logger.info(f"CRYPTO_ACTION: DECRYPT | Tenant: {tenant['id']} ({tenant['name']})")
        
        hex_content = await file.read()
        ciphertext = bytes.fromhex(hex_content.decode('utf-8').strip())
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {
            "decrypted_content": plaintext.decode('utf-8'),
            "tenant_context": tenant['name']
        }
    except Exception as e:
        logger.error(f"CRYPTO_FAILURE | Tenant: {tenant['id']} | Error: Decryption logic failure.")
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid file or corrupted data.")
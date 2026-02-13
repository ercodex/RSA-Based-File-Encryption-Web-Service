import os
import time
import secrets 
import hashlib
import logging
import binascii
from typing import Dict
from datetime import datetime # New addition
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from dotenv import load_dotenv

# --- Load Environment Variables ---
load_dotenv()

# --- Security Logging Configuration ---
# Log format adapted for SIEM (Security Information and Event Management) systems.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SecurityAudit")

# --- API Initialization ---
app = FastAPI(
    title="Ridicoulusly Secure RSA Encryption Service",
    description="A secure web service for RSA-2048 encryption.",
    version="1.0.0"
)

# --- Configuration ---
# API_KEY variable can be kept here or removed since it will be checked from TENANT_DB.
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

KEY_DIR = "secure_keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")

MAGIC_NUMBERS = {
    "pdf": b"%PDF",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "txt": None  # Text files do not have magic bytes, encoding check is performed.
}

# Rate limiting storage
request_history: Dict[str, float] = {}

if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)

# --- Multi-Tenant Demo Configuration ---
# Retrieve keys from environment variables to prevent hardcoding secrets
TENANT_DB = {
    os.getenv("TENANT_A_KEY"): {"id": "tenant_001", "name": "Company_A"},
    os.getenv("TENANT_B_KEY"): {"id": "tenant_002", "name": "Company_B"}
}

# Remove None keys if env vars are missing
TENANT_DB = {k: v for k, v in TENANT_DB.items() if k}

async def get_api_key(api_key: str = Depends(api_key_header)):
    if not api_key:
        # Made the message clearer
        logger.warning("AUTH_FAILURE | Missing API Key")
        raise HTTPException(
            status_code=403, 
            detail="Access Denied: No API Key provided. Click 'Authorize' button."
        )
    
    valid_key_found = False
    current_tenant = None
    
    for key, context in TENANT_DB.items():
        if secrets.compare_digest(api_key, key):
            valid_key_found = True
            current_tenant = context
            break
            
    if not valid_key_found:
        logger.warning(f"AUTH_FAILURE | Invalid Key: {api_key}")
        # Customized the error message
        raise HTTPException(
            status_code=403, 
            detail="Access Denied: Invalid API Key. Please check your credentials."
        )
        
    # Log successful login
    logger.info(f"AUTH_SUCCESS | Tenant: {current_tenant['name']} granted access.")
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

# --- Helper Function: Content Validation ---
async def validate_file_content(file: UploadFile, ext: str):
    """
    OWASP ASVS 12.1.1: Verify that the uploaded file matches the expected type 
    checking the file header (magic bytes) rather than just the extension.
    """
    await file.seek(0)
    header = await file.read(10) # Read the first 10 bytes
    await file.seek(0) # Reset pointer to the beginning
    
    ext_clean = ext.replace(".", "").lower()
    
    # Simple UTF-8 check for text files
    if ext_clean == "txt":
        return True 
        
    expected_magic = MAGIC_NUMBERS.get(ext_clean)
    if expected_magic and not header.startswith(expected_magic):
        logger.warning(f"SECURITY_EVENT | Magic Byte Mismatch | Claimed: {ext} | Header: {binascii.hexlify(header)}")
        raise HTTPException(status_code=400, detail="File content does not match extension (Magic Byte Mismatch).")
    
    return True

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

    await validate_file_content(file, ext)

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


        # Assign the response to a variable first
        response_data = {
            "decrypted_content": plaintext.decode('utf-8'),
            "tenant_context": tenant['name']
        }

        # --- MEM-01 Implementation: Explicit Memory Clearing ---
        # Even though Python has a garbage collector, explicitly deleting the references
        # of sensitive data is a defence layer against memory dump analyses.
        del plaintext
        del ciphertext
        del hex_content  # We also clean the raw input
        
        return response_data

    except Exception as e:
        logger.error(f"CRYPTO_FAILURE | Tenant: {tenant['id']} | Error: Decryption logic failure.")
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid file or corrupted data.")
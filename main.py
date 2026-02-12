import os
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from fastapi.responses import FileResponse

app = FastAPI(title="Ridiculously Secure RSA Encryption Service")

# --- AUTHENTICATION ---
# Simple API Key for multi-tenant simulation (Question 4a)
API_KEY = "123"
api_key_header = APIKeyHeader(name="X-API-KEY")

def validate_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized: Invalid API Key")
    return api_key

# --- CRYPTOGRAPHY SETUP ---
# Generate RSA Key Pair (In production, these would be stored in a Key Vault)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

@app.get("/")
def health_check():
    return {"status": "Service is up and running"}

@app.post("/encrypt", dependencies=[Depends(validate_api_key)])
async def encrypt_file(file: UploadFile = File(...)):
    content = await file.read()
    
    if len(content) > 190:
        raise HTTPException(status_code=400, detail="File too large.")

    try:
        ciphertext = public_key.encrypt(
            content,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        enc_filename = f"enc_{file.filename}"
        with open(enc_filename, "wb") as f:
            f.write(ciphertext)
            
        return FileResponse(path=enc_filename, filename=enc_filename, media_type='application/octet-stream')
        
    except Exception:
        raise HTTPException(status_code=500, detail="Internal encryption error")

@app.post("/decrypt", dependencies=[Depends(validate_api_key)])
async def decrypt_file(file: UploadFile = File(...)):
    """Handles RSA decryption (Question 1a)"""
    encrypted_content = await file.read()
    
    try:
        plaintext = private_key.decrypt(
            encrypted_content,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"decrypted_data": plaintext.decode('utf-8')}
    except Exception:
        # Security: Generic error message to prevent side-channel analysis
        raise HTTPException(status_code=400, detail="Decryption failed: Invalid file or key.")
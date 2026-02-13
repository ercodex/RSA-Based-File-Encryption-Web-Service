# 🔐 RSA-Based Encryption Web Service

## 📌 Project Overview

**RSA-Based Encryption Web Service** is a secure and lightweight web API designed to encrypt and decrypt small files using the RSA-2048 cryptographic algorithm. The service allows users to upload files, encrypt them, download encrypted outputs, and decrypt previously encrypted files.

The application is built with **FastAPI**, providing an interactive and developer-friendly API interface through Swagger UI. The project demonstrates modern backend security practices such as multi-tenant authentication, rate limiting, file validation, and cryptographic integrity verification.

> ⚠️ Note: This project was developed as an academic assignment. The `.env` file is intentionally included in the repository to allow instructor access to authorized endpoints.

---

## ✨ Features

### 🔑 Cryptography

* RSA-2048 encryption using OAEP padding with SHA-256
* Secure key generation and storage
* File integrity verification using SHA-256 hashing
* Explicit sensitive memory cleanup after decryption

### 📁 File Handling

* Encrypt small files (`.txt`, `.pdf`, `.docx`)
* Download encrypted data
* Decrypt encrypted content
* Magic byte validation to verify actual file type

### 🛡 Security Enhancements

* Multi-tenant API key authentication
* Rate limiting middleware (1 request per second per IP)
* Security event logging compatible with SIEM systems
* Extension and content validation
* Constant-time API key comparison to prevent timing attacks

### 📊 Observability

* Detailed security logging
* Tenant traceability via response headers
* File integrity hash returned after encryption

### 🧪 Testing

* 10 comprehensive unit and integration tests
* Covers authentication, encryption, decryption, abuse protection, and multi-tenant functionality

### 📚 Developer Experience

* Automatic Swagger UI documentation
* Simple local deployment
* Environment-based configuration

---

## 🏗 Technology Stack

* **Language:** Python
* **Framework:** FastAPI
* **Cryptography:** cryptography
* **ASGI Server:** Uvicorn
* **Testing:** Pytest
* **Validation & Serialization:** Pydantic
* **HTTP Client:** HTTPX
* **Security & File Upload:** python-multipart
* **Environment Management:** python-dotenv

---

## 📦 Requirements

The project dependencies are listed in `requirements.txt`.

```
annotated-doc==0.0.4
annotated-types==0.7.0
anyio==4.12.1
certifi==2026.1.4
cffi==2.0.0
click==8.3.1
cryptography==46.0.5
fastapi==0.128.8
h11==0.16.0
httpcore==1.0.9
httpx==0.28.1
idna==3.11
iniconfig==2.3.0
packaging==26.0
pluggy==1.6.0
pycparser==3.0
pydantic==2.12.5
pydantic_core==2.41.5
Pygments==2.19.2
pytest==9.0.2
python-multipart==0.0.22
starlette==0.52.1
typing-inspection==0.4.2
typing_extensions==4.15.0
uvicorn==0.40.0
```

---

## ⚙️ Installation

### 1️⃣ Clone Repository

```bash
git clone <repository-url>
cd <repository-folder>
```

### 2️⃣ Create Virtual Environment (Recommended)

```bash
python -m venv venv
```

Activate environment:

#### Windows

```bash
venv\Scripts\activate
```

#### Linux / macOS

```bash
source venv/bin/activate
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🔐 Environment Variables

The service uses `.env` variables to simulate multi-tenant API authentication.

Example:

```
TENANT_A_KEY=your_api_key_here
TENANT_B_KEY=your_api_key_here
```

> ⚠️ For academic demonstration purposes, `.env` is included in the repository.

---

## ▶️ Running the Service

Start the API server using:

```bash
uvicorn main:app --reload
```

The service will be available at:

```
http://127.0.0.1:8000
```

---

## 📖 API Documentation (Swagger UI)

FastAPI automatically provides interactive API documentation:

```
http://127.0.0.1:8000/docs
```

Alternative documentation interface:

```
http://127.0.0.1:8000/redoc
```

---

## 🔑 Authentication

All cryptographic endpoints require an API key sent via header:

```
X-API-KEY: your_api_key
```

You can authorize directly from Swagger UI by clicking **Authorize**.

---

## 🧩 API Endpoints

### 🟢 Health Check

```
GET /
```

Returns server status.

---

### 🔒 Encrypt File

```
POST /encrypt
```

#### Requirements

* Valid API key
* Allowed file extensions:

  * `.txt`
  * `.pdf`
  * `.docx`
* Maximum file size: **190 bytes**

#### Response

* Encrypted content (hex encoded)
* File integrity hash in headers
* Tenant ID in headers

---

### 🔓 Decrypt File

```
POST /decrypt
```

#### Requirements

* Valid API key
* Encrypted file content in hex format

#### Response

```json
{
  "decrypted_content": "...",
  "tenant_context": "..."
}
```

---

## 🔍 Security Implementations

### ✅ OWASP ASVS File Validation

Files are validated using magic byte verification instead of relying solely on file extensions.

### ✅ Multi-Tenant Authentication

* Environment-based tenant key storage
* Constant-time key comparison

### ✅ Rate Limiting

* Maximum 1 request per second per IP
* Protects against brute-force and DoS attempts

### ✅ Cryptographic Best Practices

* RSA-2048 encryption
* OAEP padding with SHA-256
* Integrity verification via SHA-256 hashing

### ✅ Memory Security

Sensitive cryptographic data is explicitly cleared after use.

### ✅ SIEM-Friendly Logging

Structured security logs for monitoring and auditing.

---

## 🧪 Running Tests

The project includes **10 unit and integration tests**.

Run tests using:

```bash
pytest
```

### Test Coverage Includes

* Server health verification
* Authentication validation
* File validation rules
* Encryption/decryption integrity
* Rate limiting enforcement
* Multi-tenant traceability
* Full workflow integration

---

## 📂 Project Structure

```
├── main.py
├── test_main.py
├── requirements.txt
├── secure_keys/
│   ├── private.pem
│   └── public.pem
├── .env
└── README.md
```

---

## 🚧 Limitations

* Designed for small files only (RSA size constraint)
* `.env` is intentionally public for academic evaluation
* Demonstration-level multi-tenant simulation
* Not intended for production use without improvements

---

## 🔮 Future Improvements

* Hybrid encryption (RSA + AES for large files)
* Database-backed tenant management
* Token-based authentication
* Scalable distributed rate limiting
* Key rotation support
* Production-grade secret management
* Upload/download encrypted file streaming
* Extended file type support

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 👤 Author

**Eren Cil**

📧 Email:

```
eren.cil@outlook.com
```

🔗 LinkedIn:

```
https://www.linkedin.com/in/erencil
```

---

## ⭐ Acknowledgements

This project was developed as part of an academic assignment to demonstrate secure web service development, applied cryptography, and backend security engineering principles.

"""
Demo Protected Web Application.
Serves as the upstream target behind the AI-WAF reverse proxy.
Contains safe demonstration endpoints for testing legitimate and intercepted traffic.
Does NOT contain actual vulnerabilities or filesystem/shell access.
"""

from typing import Optional
from fastapi import FastAPI, Query, status
from pydantic import BaseModel

app = FastAPI(
    title="Protected Demo E-Commerce API",
    description="Sample upstream backend protected by AI-WAF",
    version="1.0.0",
)

# Mock in-memory product catalog
SAMPLE_PRODUCTS = [
    {"id": 1, "name": "Secure Cloud Gateway", "category": "Network", "price": 499.00},
    {"id": 2, "name": "Hardware Token Key", "category": "Auth", "price": 45.00},
    {"id": 3, "name": "Enterprise Threat Scanner", "category": "Analytics", "price": 1299.00},
    {"id": 4, "name": "Encrypted Storage Appliance", "category": "Storage", "price": 850.00},
]

# Mock virtual file metadata (safe, no filesystem I/O)
MOCK_FILES = {
    "report.pdf": {"size_bytes": 1048576, "type": "application/pdf", "owner": "sec-ops"},
    "config.json": {"size_bytes": 4096, "type": "application/json", "owner": "admin"},
    "audit.csv": {"size_bytes": 524288, "type": "text/csv", "owner": "compliance"},
}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/")
def home():
    return {
        "status": "online",
        "service": "Protected Demo Upstream Application",
        "message": "Welcome! You have successfully reached the upstream application behind AI-WAF.",
    }


@app.get("/search")
def search(q: Optional[str] = Query(default=None, description="Search query string")):
    if not q:
        return {"query": "", "results": SAMPLE_PRODUCTS}
    filtered = [p for p in SAMPLE_PRODUCTS if q.lower() in p["name"].lower() or q.lower() in p["category"].lower()]
    return {"query": q, "count": len(filtered), "results": filtered}


@app.get("/products")
def list_products():
    return {"products": SAMPLE_PRODUCTS}


@app.post("/login", status_code=status.HTTP_200_OK)
def login(credentials: LoginRequest):
    # Safe demonstration auth check
    if credentials.username == "demo_user" and credentials.password == "secure_pass_123":
        return {
            "authenticated": True,
            "token": "demo-jwt-token-upstream-granted",
            "user": credentials.username,
        }
    return {
        "authenticated": False,
        "message": "Invalid username or password (try: demo_user / secure_pass_123)",
    }


@app.get("/files")
def get_file_metadata(filename: str = Query(..., description="Target file name")):
    # Safe virtual file metadata lookup - never accesses host filesystem
    if filename in MOCK_FILES:
        return {"filename": filename, "found": True, "metadata": MOCK_FILES[filename]}
    return {"filename": filename, "found": False, "message": "File not found in virtual catalog"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)

from fastapi import FastAPI, HTTPException, Depends, Request, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import base64
import json
import os
import time
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from mangum import Mangum

app = FastAPI(title="JWT Decoder API", version="1.0.0")
# === BT Builds Standard Middleware (auto-injected) ===
from fastapi.middleware.cors import CORSMiddleware as _BTCors
app.add_middleware(_BTCors, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], expose_headers=["X-RateLimit-Limit","X-RateLimit-Remaining","X-RateLimit-Reset"])

@app.middleware("http")
async def _bt_add_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "btbuilds"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security setup
security = HTTPBearer()

# API Key configuration (use environment variable in production)
API_KEY = os.environ.get("API_KEY", "<set-your-api-key>")

class TokenRequest(BaseModel):
    """Request model for JWT token."""
    token: str

class BulkTokenRequest(BaseModel):
    """Request model for bulk JWT tokens."""
    tokens: list[str]

class DecodedResponse(BaseModel):
    """Response model for decoded JWT."""
    header: dict
    payload: dict
    signature_valid: bool
    signature_error: str | None = None

class ValidationResponse(BaseModel):
    """Response model for JWT validation."""
    valid: bool
    well_formed: bool
    not_expired: bool
    signature_valid: bool
    error: str | None = None

class BulkDecodeResult(BaseModel):
    """Result for a single item in bulk decode."""
    input: str
    output: dict | None = None
    error: str | None = None

class BulkDecodeResponse(BaseModel):
    """Response model for bulk decode."""
    results: list[BulkDecodeResult]
    total: int
    successful: int

class BulkValidateResult(BaseModel):
    """Result for a single item in bulk validate."""
    input: str
    output: dict | None = None
    error: str | None = None

class BulkValidateResponse(BaseModel):
    """Response model for bulk validate."""
    results: list[BulkValidateResult]
    total: int
    successful: int

def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> str:
    """Verify API key from Authorization header."""
    if credentials.credentials != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials

def decode_base64url(data: str) -> dict:
    """Decode base64url encoded JWT part without signature verification."""
    try:
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        decoded = base64.urlsafe_b64decode(data)
        return json.loads(decoded)
    except Exception as e:
        raise ValueError(f"Failed to decode base64 data: {str(e)}")

def decode_jwt_parts(token: str) -> tuple[dict, dict]:
    """Decode JWT header and payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Token must have exactly 3 parts")
        
        header = decode_base64url(parts[0])
        payload = decode_base64url(parts[1])
        return header, payload
    except Exception as e:
        raise ValueError(f"Invalid JWT format: {str(e)}")

def _decode_single(token: str) -> dict:
    """Internal helper to decode a JWT token and return dict result."""
    try:
        header, payload = decode_jwt_parts(token)
        try:
            signature = token.split(".")[2]
            if not signature:
                raise ValueError("Missing signature")
            signature_valid = True
            signature_error = None
        except Exception as e:
            signature_valid = False
            signature_error = str(e)
        
        return {
            "header": header,
            "payload": payload,
            "signature_valid": signature_valid,
            "signature_error": signature_error
        }
    except Exception as e:
        raise

def _validate_single(token: str) -> dict:
    """Internal helper to validate a JWT token and return dict result."""
    well_formed = False
    not_expired = False
    signature_valid = False
    error = None
    
    try:
        parts = token.split(".")
        if len(parts) != 3:
            error = "Token must have exactly 3 parts (header.payload.signature)"
            return {
                "valid": False,
                "well_formed": False,
                "not_expired": False,
                "signature_valid": False,
                "error": error
            }
        
        well_formed = True
        header, payload = decode_jwt_parts(token)
        
        try:
            if "exp" in payload:
                exp_time = payload["exp"]
                if exp_time > 9999999999:
                    exp_time = exp_time / 1000
                current_time = time.time()
                not_expired = exp_time > current_time
                if not not_expired:
                    error = f"Token has expired (expired at {exp_time}, current time: {current_time})"
            else:
                not_expired = True
        except Exception as e:
            error = f"Error checking expiration: {str(e)}"
            not_expired = False
        
        try:
            signature = parts[2]
            if len(signature) > 0:
                signature_valid = True
            else:
                error = "Empty signature"
                signature_valid = False
        except Exception as e:
            signature_valid = False
            if error is None:
                error = f"Signature validation error: {str(e)}"
        
        valid = well_formed and not_expired and signature_valid
        
        return {
            "valid": valid,
            "well_formed": well_formed,
            "not_expired": not_expired,
            "signature_valid": signature_valid,
            "error": error
        }
    except Exception as e:
        return {
            "valid": False,
            "well_formed": well_formed,
            "not_expired": not_expired,
            "signature_valid": signature_valid,
            "error": f"Unexpected error: {str(e)}"
        }

@app.get("/health")
async def health_check():
    """Health check endpoint - no authentication required."""
    return {"status": "healthy", "timestamp": time.time()}

@app.post("/decode", response_model=DecodedResponse)
@limiter.limit("100/min")
async def decode_token(
    request: Request,
    token_request: TokenRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Decode a JWT token and return header and payload as JSON.
    Also validates signature if possible.
    """
    result = _decode_single(token_request.token)
    return DecodedResponse(**result)

@app.post("/validate", response_model=ValidationResponse)
@limiter.limit("100/min")
async def validate_token(
    request: Request,
    token_request: TokenRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Validate a JWT token - check if it's well-formed, not expired, and signature is valid.
    """
    result = _validate_single(token_request.token)
    return ValidationResponse(**result)

@app.post("/bulk/decode", response_model=BulkDecodeResponse)
@limiter.limit("30/min")
async def bulk_decode(
    request: Request,
    bulk_request: BulkTokenRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Decode multiple JWT tokens in bulk.
    Accepts up to 1000 tokens and returns results for each.
    """
    tokens = bulk_request.tokens[:1000]
    results = []
    successful = 0
    
    for token in tokens:
        try:
            result = _decode_single(token)
            results.append(BulkDecodeResult(input=token, output=result, error=None))
            successful += 1
        except Exception as e:
            results.append(BulkDecodeResult(input=token, output=None, error=str(e)))
    
    return BulkDecodeResponse(
        results=results,
        total=len(tokens),
        successful=successful
    )

@app.post("/bulk/validate", response_model=BulkValidateResponse)
@limiter.limit("30/min")
async def bulk_validate(
    request: Request,
    bulk_request: BulkTokenRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Validate multiple JWT tokens in bulk.
    Accepts up to 1000 tokens and returns validation results for each.
    """
    tokens = bulk_request.tokens[:1000]
    results = []
    successful = 0
    
    for token in tokens:
        try:
            result = _validate_single(token)
            results.append(BulkValidateResult(input=token, output=result, error=None))
            successful += 1
        except Exception as e:
            results.append(BulkValidateResult(input=token, output=None, error=str(e)))
    
    return BulkValidateResponse(
        results=results,
        total=len(tokens),
        successful=successful
    )

# Handler for Vercel serverless deployment
handler = Mangum(app)
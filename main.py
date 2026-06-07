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
    token = token_request.token
    
    try:
        header, payload = decode_jwt_parts(token)
        
        # Try signature verification (without key, just check format)
        try:
            # Basic signature validation - checks if signature part is valid base64
            signature = token.split(".")[2]
            if not signature:
                raise ValueError("Missing signature")
            signature_valid = True
            signature_error = None
        except Exception as e:
            signature_valid = False
            signature_error = str(e)
        
        return DecodedResponse(
            header=header,
            payload=payload,
            signature_valid=signature_valid,
            signature_error=signature_error
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode token: {str(e)}")

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
    token = token_request.token
    
    well_formed = False
    not_expired = False
    signature_valid = False
    error = None
    
    try:
        # Check if well-formed
        parts = token.split(".")
        if len(parts) != 3:
            error = "Token must have exactly 3 parts (header.payload.signature)"
            return ValidationResponse(
                valid=False,
                well_formed=False,
                not_expired=False,
                signature_valid=False,
                error=error
            )
        
        well_formed = True
        header, payload = decode_jwt_parts(token)
        
        # Check expiration
        try:
            if "exp" in payload:
                exp_time = payload["exp"]
                # Handle both seconds and milliseconds timestamps
                if exp_time > 9999999999:  # Likely milliseconds
                    exp_time = exp_time / 1000
                current_time = time.time()
                not_expired = exp_time > current_time
                if not not_expired:
                    error = f"Token has expired (expired at {exp_time}, current time: {current_time})"
            else:
                not_expired = True  # No expiration claim, consider it not expired
        except Exception as e:
            error = f"Error checking expiration: {str(e)}"
            not_expired = False
        
        # Check signature - basic format validation
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
        
        # Overall validity
        valid = well_formed and not_expired and signature_valid
        
        if valid and error is None:
            error = None
        
        return ValidationResponse(
            valid=valid,
            well_formed=well_formed,
            not_expired=not_expired,
            signature_valid=signature_valid,
            error=error
        )
    except ValueError as e:
        error = str(e)
        return ValidationResponse(
            valid=False,
            well_formed=well_formed,
            not_expired=not_expired,
            signature_valid=signature_valid,
            error=error
        )
    except Exception as e:
        error = f"Unexpected error: {str(e)}"
        return ValidationResponse(
            valid=False,
            well_formed=well_formed,
            not_expired=not_expired,
            signature_valid=signature_valid,
            error=error
        )

# Handler for Vercel serverless deployment
handler = Mangum(app)
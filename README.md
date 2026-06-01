# JWT Decoder API

A FastAPI service for decoding and validating JWT tokens with API key authentication and rate limiting.

## Features

- JWT Decode: Extract and return header and payload from JWT tokens
- JWT Validate: Check if tokens are well-formed, not expired, and have valid signatures
- API Key Authentication: Secure endpoints with Bearer token authentication
- Rate Limiting: 100 requests per minute on authenticated routes
- Vercel Ready: Deployable as a serverless function

## Installation

```bash
pip install -r requirements.txt
```

## Running Locally

```bash
uvicorn main:app --reload --port 8000
```

## API Endpoints

### GET /health

Health check endpoint - no authentication required.

**Example:**
```bash
curl -X GET http://localhost:8000/health
```

**Response:**
```json
{"status": "healthy", "timestamp": 1704067200.0}
```

---

### POST /decode

Decode a JWT token and return header and payload as JSON. Requires authentication.

**Headers:**
```
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

**Body:**
```json
{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
```

**Example:**
```bash
curl -X POST https://jwt-decoder-delta.vercel.app/decode \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
```

**Response:**
```json
{
  "header": {"alg": "HS256", "typ": "JWT"},
  "payload": {"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
  "signature_valid": true,
  "signature_error": null
}
```

---

### POST /validate

Validate a JWT token - check if it's well-formed, not expired, and signature is valid. Requires authentication.

**Headers:**
```
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

**Body:**
```json
{"token": "<jwt-token>"}
```

**Example:**
```bash
curl -X POST https://jwt-decoder-delta.vercel.app/validate \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
```

**Response:**
```json
{
  "valid": true,
  "well_formed": true,
  "not_expired": true,
  "signature_valid": true,
  "error": null
}
```

**Error Response (Expired Token):**
```json
{
  "valid": false,
  "well_formed": true,
  "not_expired": false,
  "signature_valid": true,
  "error": "Token has expired (expired at 1516239022, current time: 1704067200.0)"
}
```

---

## Deployment to Vercel

The API is already deployed at https://jwt-decoder-delta.vercel.app

To deploy your own:
1. Push this directory to a Git repository
2. Connect your repository to Vercel
3. Vercel will automatically detect the vercel.json configuration
4. Deploy!

## Environment Variables (Production)

- API_KEY: Your secret API key (set in Vercel dashboard)

## Rate Limiting

The /decode and /validate endpoints are rate-limited to 100 requests per minute per IP address. The /health endpoint is exempt from rate limiting.

## Error Handling

- 400 Bad Request: Invalid JWT format or decoding errors
- 401 Unauthorized: Missing or invalid API key
- 429 Too Many Requests: Rate limit exceeded
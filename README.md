# Auth & API Key System

A robust, production-ready authentication and API key management system built with **FastAPI**, **SQLAlchemy (Async)**, and **PostgreSQL**.

## Features

- **Dual Authentication**: Supports both **JWT Bearer Tokens** (for users) and **API Keys** (for services/scripts).
- **Password Policy**: Enforced password complexity requirements (minimum 8 characters, uppercase, lowercase, numbers, special characters).
- **Secure API Key Storage**: API keys are hashed using SHA-256 before storage.
- **API Key Expiration**: Maximum 90-day expiration policy for all API keys.
- **Refresh Tokens**: Securely rotate access tokens without re-login.
- **Rate Limiting**: Comprehensive rate limiting on all critical endpoints to prevent abuse.
- **Dual Swagger Authorization**: Separate authorization fields for JWT and API keys in Swagger UI.
- **Structured Logging**: JSON-formatted logs for observability.
- **Async Database**: High-performance async operations with `asyncpg`.
- **Comprehensive Testing**: Full test suite using `pytest` and `httpx`.

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL (Async via SQLAlchemy + asyncpg)
- **Validation**: Pydantic V2
- **Security**: 
  - OAuth2 with Password Flow
  - Bcrypt for password hashing
  - SHA-256 for API key hashing
  - JWT tokens with `python-jose`
- **Rate Limiting**: SlowAPI
- **Testing**: Pytest, Httpx

## Setup

### 1. Prerequisites
- Python 3.10+
- PostgreSQL installed and running

### 2. Installation

Clone the repository and install dependencies:

```bash
git clone <repo_url>
cd auth-api-key-system
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac/Linux:
# source venv/bin/activate

pip install -r requirements.txt
```

### 3. Configuration

Create a `.env` file in the root directory:

```ini
DATABASE_URL=postgresql+asyncpg://user:password@localhost/auth_db
SECRET_KEY=your_super_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
TESTING=false
```

### 4. Database Setup

Ensure your PostgreSQL database exists:

```sql
CREATE DATABASE auth_db;
```

The application automatically initializes tables on startup.

## Running the Application

```bash
uvicorn app.main:app --reload
```

Server will start at `http://127.0.0.1:8000`.

Explore the **Interactive API Docs** at `http://127.0.0.1:8000/docs`.

## API Usage Examples

### 1. User Signup

Password must meet complexity requirements:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number (0-9)
- At least one special character

```bash
curl -X POST http://localhost:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'
```

### 2. Login (Get Tokens)

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'
```

Response:
```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "rt_...",
  "token_type": "bearer"
}
```

### 3. Refresh Access Token

```bash
curl -X POST "http://localhost:8000/auth/refresh?refresh_token=rt_..." \
  -H "Content-Type: application/json"
```

### 4. Create API Key

API keys automatically expire in 90 days (or less if specified):

```bash
curl -X POST http://localhost:8000/keys/create \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Service A", "expires_in_days": 30}'
```

Response:
```json
{
  "id": "...",
  "key": "sk_...",
  "name": "Service A",
  "expires_at": "2025-01-06T...",
  "is_active": true
}
```

**Important**: The API key is only shown once. Store it securely!

### 5. List API Keys

```bash
curl http://localhost:8000/keys/list \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### 6. Revoke API Key

```bash
curl -X DELETE http://localhost:8000/keys/revoke/{key_id} \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### 7. Access Protected Routes

```bash
# Using JWT
curl http://localhost:8000/protected/user-only \
  -H "Authorization: Bearer <ACCESS_TOKEN>"

# Using API Key
curl http://localhost:8000/protected/service-only \
  -H "Authorization: Bearer sk_..."
```

## Rate Limits

The following rate limits are enforced:

| Endpoint | Limit | Purpose |
|----------|-------|---------|
| `POST /auth/signup` | 5/hour | Prevent spam registration |
| `POST /auth/login` | 10/minute | Prevent brute-force attacks |
| `POST /auth/refresh` | 20/hour | Prevent token abuse |
| `POST /keys/create` | 10/hour | Prevent key spam |
| `GET /keys/list` | 30/minute | Allow dashboard access |
| `DELETE /keys/revoke/{key_id}` | 20/hour | Prevent abuse |

When rate limit is exceeded, the API returns `429 Too Many Requests`.

## Swagger UI

The interactive documentation at `/docs` features:

- **Dual Authorization Buttons**: Separate fields for JWT tokens and API keys
- **Persistent Authorization**: Credentials persist across page refreshes
- **Clear Documentation**: Each endpoint shows which authentication method it requires
- **Try It Out**: Test all endpoints directly from the browser

### Using Swagger UI:

1. **For JWT Authentication**:
   - Click "JWTBearer (Authorize)" button
   - Enter your access token from `/auth/login`
   - Click "Authorize"

2. **For API Key Authentication**:
   - Click "APIKeyBearer (Authorize)" button
   - Enter your API key from `/keys/create` (starts with `sk_`)
   - Click "Authorize"

## Testing

Run the full test suite:

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_auth.py
```

**Test Coverage**:
- ✅ Password validation (6 tests)
- ✅ Authentication flow (3 tests)
- ✅ API key management (3 tests)
- ✅ Protected routes (1 test)

> **Note**: Tests automatically disable rate limiting and use transaction rollbacks to keep the database clean.

## Security Features

### Password Security
- **Bcrypt Hashing**: Passwords are hashed with bcrypt (adaptive hashing)
- **Complexity Requirements**: Enforced password policy prevents weak passwords
- **No Plain Text Storage**: Passwords are never stored in plain text

### API Key Security
- **SHA-256 Hashing**: API keys are hashed before storage
- **One-Time Display**: Keys are only shown once upon creation
- **Automatic Expiration**: Maximum 90-day lifespan
- **Revocation Support**: Keys can be revoked immediately

### Token Security
- **JWT Tokens**: Signed with HS256 algorithm
- **Refresh Token Rotation**: Old refresh tokens are revoked when used
- **Expiration**: Access tokens expire in 30 minutes (configurable)

### Additional Security
- **Rate Limiting**: Prevents brute-force and DoS attacks
- **CORS**: Configurable cross-origin resource sharing
- **Async Operations**: Non-blocking I/O for better performance under load

## Project Structure

```
.
├── app
│   ├── routers/
│   │   ├── auth.py          # Authentication endpoints
│   │   ├── keys.py          # API key management
│   │   └── protected.py     # Example protected routes
│   ├── auth.py              # Auth logic (hashing, JWT, dependencies)
│   ├── config.py            # Configuration settings
│   ├── database.py          # DB connection & session
│   ├── logging_config.py    # Structured logging setup
│   ├── main.py              # App entrypoint & OpenAPI config
│   ├── models.py            # SQLAlchemy models
│   ├── schemas.py           # Pydantic models
│   └── utils.py             # Utility functions (password validation, hashing)
├── tests/
│   ├── conftest.py          # Pytest configuration
│   ├── test_auth.py         # Authentication tests
│   ├── test_keys.py         # API key tests
│   └── test_protected.py    # Protected route tests
├── .env                     # Environment variables (not in repo)
├── .env.example             # Example environment file
├── .gitignore
├── pytest.ini               # Pytest configuration
├── requirements.txt         # Python dependencies
└── README.md
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `SECRET_KEY` | JWT signing key | Required |
| `ALGORITHM` | JWT algorithm | HS256 |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | 30 |
| `TESTING` | Disable rate limiting for tests | false |

## API Endpoints

### Authentication (`/auth`)
- `POST /auth/signup` - Register new user
- `POST /auth/login` - Login and get tokens
- `POST /auth/refresh` - Refresh access token
- `GET /auth/me` - Get current user info

### API Keys (`/keys`)
- `POST /keys/create` - Create new API key
- `GET /keys/list` - List user's API keys
- `DELETE /keys/revoke/{key_id}` - Revoke API key

### Protected Routes (`/protected`)
- `GET /protected/user-only` - Requires JWT or API key
- `GET /protected/service-only` - Requires API key only

### System
- `GET /` - API information
- `GET /health` - Health check
- `GET /docs` - Swagger UI
- `GET /redoc` - ReDoc documentation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## License

This project is licensed under the MIT License.

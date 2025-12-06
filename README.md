# Auth & API Key System

A robust, production-ready authentication and API key management system built with **FastAPI**, **SQLAlchemy (Async)**, and **PostgreSQL**.

## Features

- **Dual Authentication**: Supports both **JWT Bearer Tokens** (for users) and **API Keys** (for services/scripts).
- **Role-Based Access Control (RBAC)**: Distinguish between `admin` and `user` roles.
- **API Key Scopes**: Granular permissions for API keys (e.g., `read`, `write`).
- **Refresh Tokens**: Securely rotate access tokens without re-login.
- **Rate Limiting**: Integrated `SlowAPI` to prevent abuse.
- **Structured Logging**: JSON-formatted logs for observability.
- **Async Database**: High-performance async operations with implementation of `asyncpg`.
- **Comprehensive Testing**: Full test suite using `pytest` and `httpx`.

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL (Async via SQLAlchemy + asyncpg)
- **Validation**: Pydantic V2
- **Security**: OAuth2 with Password Flow, Bcrypt hashing
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
```

### 4. Database Setup

Ensure your PostgreSQL database exists:

```sql
CREATE DATABASE auth_db;
```

The application normally initializes tables on startup (dev mode).

## Running the Application

```bash
uvicorn app.main:app --reload
```

Server will start at `http://127.0.0.1:8000`.
Explore the **Interactive API Docs** at `http://127.0.0.1:8000/docs`.

## API Usage Examples

### 1. User Signup
```bash
curl -X POST http://localhost:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword"}'
```

### 2. Login (Get Tokens)
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword"}'
```
Response:
```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "rt_...",
  "token_type": "bearer"
}
```

### 3. Create Scoped API Key
```bash
curl -X POST http://localhost:8000/keys/create \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Service A", "scopes": "read"}'
```

### 4. Access Protected Route
```bash
# Using JWT
curl http://localhost:8000/protected/user-only -H "Authorization: Bearer <ACCESS_TOKEN>"

# Using API Key
curl http://localhost:8000/protected/service-only -H "Authorization: Bearer sk_..."
```

## Testing

Run the full test suite with:

```bash
pytest
```

> **Note**: Tests run against the configured database using transaction rollbacks to keep data clean.

## Project Structure

```
.
├── app
│   ├── routers        # API endpoints (auth, keys, protected)
│   ├── auth.py        # Core auth logic (hashing, JWT, dependencies)
│   ├── database.py    # DB connection & session
│   ├── main.py        # App entrypoint
│   ├── models.py      # SQLAlchemy models
│   ├── schemas.py     # Pydantic models
│   └── logging_config.py
├── tests              # Pytest suite
├── requirements.txt
└── .env
```

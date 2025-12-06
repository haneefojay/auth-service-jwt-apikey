from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .database import init_db
from .routers import auth, keys, protected
from .logging_config import logger

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create database tables
    logger.info("Starting up application and initializing database...")
    await init_db()
    yield
    # Shutdown
    logger.info("Shutting down application...")

app = FastAPI(
    title="Authentication & API Key System",
    description="A mini authentication system supporting both JWT and API key access",
    version="1.0.0",
    lifespan=lifespan
)

# Add limiter to app so routers can use it
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware for logging requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

# Include routers
app.include_router(auth.router)
app.include_router(keys.router)
app.include_router(protected.router)

@app.get("/")
def root():
    return {
        "message": "Authentication & API Key System API",
        "version": "1.0.0",
        "endpoints": {
            "auth": "/auth/signup, /auth/login, /auth/me",
            "keys": "/keys/create, /keys/list, /keys/revoke/{key_id}, /keys/delete/{key_id}",
            "protected": "/protected/user-only, /protected/service-only, /protected/admin",
            "docs": "/docs"
        }
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}
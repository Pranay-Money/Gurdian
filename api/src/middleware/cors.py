"""
CORS Configuration
Restricted to extension origin only.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.core.config import get_settings

settings = get_settings()


def setup_cors(app: FastAPI) -> None:
    """Configure CORS for the extension origin only."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["X-Device-Token", "Content-Type", "Authorization"],
        expose_headers=["Retry-After"],
        max_age=86400,  # 24 hours
    )


def get_extension_origin() -> str:
    """Get the expected extension origin from settings."""
    origins = settings.cors_allowed_origins
    if origins:
        return origins[0]
    return "chrome-extension://*"
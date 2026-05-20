"""HTTP helpers for Flask API (production-safe errors, CORS)."""
from __future__ import annotations

import os


def is_production() -> bool:
    return os.environ.get('VERCEL_ENV') == 'production'


def public_error_message(exc: BaseException) -> str:
    """Hide implementation details from clients in production."""
    if is_production():
        return 'Internal server error'
    return str(exc)


def cors_allowed_origins() -> list[str]:
    """Vercel deployment hostnames (https) for browser CORS."""
    origins: list[str] = []
    for key in ('VERCEL_URL', 'VERCEL_BRANCH_URL', 'VERCEL_PROJECT_PRODUCTION_URL'):
        host = os.environ.get(key, '').strip()
        if host:
            origins.append(f'https://{host}')
    # Custom production domain if configured in Vercel project settings
    prod = os.environ.get('PRODUCTION_URL', '').strip()
    if prod:
        origins.append(prod if prod.startswith('https://') else f'https://{prod}')
    return origins

"""
OIDC admin SSO — authorization-code flow with PyJWT-verified ID tokens.

No extra dependencies: discovery and the token exchange use ``httpx``
(already required), ID-token signatures are checked with PyJWT's JWKS
client. The pieces are deliberately separable:

* ``make_state`` / ``check_state`` — HMAC-signed, TTL-bound state token
  (CSRF protection for the round-trip; stateless, no server session).
* ``resolve_role`` — claim → NACo AdminRole mapping.
* ``provision_user`` — create/refresh the AdminUser row for an SSO
  identity; SSO accounts get an unusable password hash so they can never
  log in locally.
* ``authenticate_code`` — the full callback: code exchange + ID-token
  verification + provisioning.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any

import httpx
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.config import OidcConfig
from naco.core.logger import get_logger
from naco.db.models import AdminRole, AdminUser

log = get_logger(__name__)

#: Seconds an authorization round-trip may take before the state expires.
STATE_TTL = 600

#: Marker prefix for password hashes of SSO-provisioned accounts. bcrypt
#: hashes start with "$2b$"; this can never match any password.
_UNUSABLE_HASH_PREFIX = "!oidc!"

# Discovery documents are tiny and stable — cache per issuer.
_discovery_cache: dict[str, dict[str, Any]] = {}
_jwks_clients: dict[str, jwt.PyJWKClient] = {}


# ---------------------------------------------------------------------------
# State token
# ---------------------------------------------------------------------------

def make_state(secret: str, now: float | None = None) -> str:
    """Return ``<nonce>.<timestamp>.<hmac>`` bound to *secret*."""
    nonce = secrets.token_urlsafe(16)
    ts = str(int(now if now is not None else time.time()))
    mac = hmac.new(secret.encode(), f"{nonce}.{ts}".encode(), hashlib.sha256)
    sig = base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")
    return f"{nonce}.{ts}.{sig}"


def check_state(secret: str, state: str, now: float | None = None) -> bool:
    try:
        nonce, ts, sig = state.rsplit(".", 2)
    except (ValueError, AttributeError):
        return False
    mac = hmac.new(secret.encode(), f"{nonce}.{ts}".encode(), hashlib.sha256)
    expected = base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")
    if not hmac.compare_digest(expected, sig):
        return False
    try:
        age = (now if now is not None else time.time()) - int(ts)
    except ValueError:
        return False
    return 0 <= age <= STATE_TTL


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

async def discover(issuer: str) -> dict[str, Any]:
    """Fetch (and cache) the provider's openid-configuration."""
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        doc = resp.json()
    _discovery_cache[issuer] = doc
    return doc


def build_auth_url(cfg: OidcConfig, doc: dict[str, Any], redirect_uri: str,
                   state: str) -> str:
    from urllib.parse import urlencode
    params = urlencode({
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(cfg.scopes),
        "state": state,
    })
    return f"{doc['authorization_endpoint']}?{params}"


# ---------------------------------------------------------------------------
# Role mapping & provisioning
# ---------------------------------------------------------------------------

_ROLE_RANK = {AdminRole.VIEWER: 0, AdminRole.OPERATOR: 1, AdminRole.SUPERUSER: 2}


def resolve_role(cfg: OidcConfig, claims: dict[str, Any]) -> AdminRole | None:
    """Map the configured claim to a NACo role; highest matching role wins.

    Returns ``None`` when nothing matches and no default_role is set —
    the caller must deny access.
    """
    raw = claims.get(cfg.role_claim)
    values = raw if isinstance(raw, list) else [raw] if raw is not None else []

    best: AdminRole | None = None
    for value in values:
        mapped = cfg.role_map.get(str(value))
        if not mapped:
            continue
        try:
            role = AdminRole(mapped)
        except ValueError:
            log.warning("oidc.role_map value %r is not a valid role", mapped)
            continue
        if best is None or _ROLE_RANK[role] > _ROLE_RANK[best]:
            best = role
    if best is not None:
        return best
    if cfg.default_role:
        try:
            return AdminRole(cfg.default_role)
        except ValueError:
            log.warning("oidc.default_role %r is not a valid role", cfg.default_role)
    return None


async def provision_user(
    db: AsyncSession, cfg: OidcConfig, claims: dict[str, Any],
) -> AdminUser | None:
    """Create or refresh the AdminUser for a verified set of claims.

    Returns ``None`` (deny) when the username claim is missing, no role
    resolves, or the local account exists but is disabled.
    """
    username = (claims.get(cfg.username_claim) or "").strip()
    if not username:
        log.warning("OIDC login without %r claim — denied", cfg.username_claim)
        return None

    role = resolve_role(cfg, claims)
    if role is None:
        log.warning("OIDC user %r matched no role and no default — denied", username)
        return None

    user = (await db.execute(
        select(AdminUser).where(AdminUser.username == username)
    )).scalar_one_or_none()

    if user is not None and not user.enabled:
        log.warning("OIDC login for disabled admin %r — denied", username)
        return None

    if user is None:
        user = AdminUser(
            username=username,
            # Unusable marker + random suffix: never verifiable as bcrypt.
            password_hash=_UNUSABLE_HASH_PREFIX + secrets.token_urlsafe(32),
            email=str(claims.get("email") or ""),
            role=role,
            is_superuser=role == AdminRole.SUPERUSER,
            enabled=True,
        )
        db.add(user)
        log.info("Provisioned admin %r from OIDC (role=%s)", username, role.value)
    else:
        if user.role != role:
            log.info("OIDC role sync for %r: %s → %s", username, user.role, role.value)
            user.role = role
            user.is_superuser = role == AdminRole.SUPERUSER
        if claims.get("email"):
            user.email = str(claims["email"])
    await db.commit()
    await db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Callback: code → verified claims → user
# ---------------------------------------------------------------------------

async def authenticate_code(
    db: AsyncSession, cfg: OidcConfig, code: str, redirect_uri: str,
) -> AdminUser | None:
    """Exchange *code*, verify the ID token, and provision the admin."""
    doc = await discover(cfg.issuer)

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(doc["token_endpoint"], data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
        })
        if resp.status_code != 200:
            log.warning("OIDC token exchange failed: %s %s", resp.status_code, resp.text[:200])
            return None
        token_response = resp.json()

    id_token = token_response.get("id_token")
    if not id_token:
        log.warning("OIDC token response missing id_token")
        return None

    try:
        jwks_client = _jwks_clients.get(cfg.issuer)
        if jwks_client is None:
            jwks_client = jwt.PyJWKClient(doc["jwks_uri"], cache_keys=True)
            _jwks_clients[cfg.issuer] = jwks_client
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256", "PS256"],
            audience=cfg.client_id,
            issuer=cfg.issuer,
        )
    except jwt.PyJWTError as exc:
        log.warning("OIDC ID-token verification failed: %s", exc)
        return None

    return await provision_user(db, cfg, claims)

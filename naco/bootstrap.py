"""First start: create the initial administrator."""
from __future__ import annotations

import logging
import secrets
import sys

from sqlalchemy import func, select

from naco.config import ConfigError, get_secrets
from naco.core.passwords import hash_password, validate_admin_password
from naco.db.engine import session_factory
from naco.db.models import AdminRole, AdminUser

log = logging.getLogger(__name__)


async def ensure_admin() -> str | None:
    """Create ``admin`` (SUPERUSER, must change password) when no admin exists.

    Uses ``NACO_ADMIN_PASSWORD`` when set, otherwise a random password that
    is printed once to stdout. Returns the password that was set, or None.
    """
    async with session_factory()() as db:
        if (await db.execute(select(func.count()).select_from(AdminUser))).scalar_one():
            return None
    password = get_secrets().admin_password
    generated = password is None
    if password is None:
        password = secrets.token_urlsafe(15)
    try:
        validate_admin_password(password)
    except ValueError as exc:
        raise ConfigError(f"NACO_ADMIN_PASSWORD: {exc}") from exc
    hashed = await hash_password(password)
    async with session_factory()() as db:
        db.add(AdminUser(username="admin", password_hash=hashed, role=AdminRole.SUPERUSER,
                         must_change_password=True))
        await db.commit()
    log.warning("Created the initial administrator 'admin' — the password must be changed at first login")
    if generated:
        # Printed, not logged: the log redaction would (rightly) mask it.
        sys.stdout.write(
            "\n  Initial administrator  ->  admin / " + password + "\n"
            "  (shown once; set NACO_ADMIN_PASSWORD to choose it yourself)\n\n"
        )
        sys.stdout.flush()
    return password

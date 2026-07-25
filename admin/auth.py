import os
import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import Request, HTTPException

from db import StaleSessionError, revalidate_user

SECRET_KEY = os.environ.get("SECRET_KEY", "changeme-set-in-env")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_token(user_id: str, role: str, customer_id: str | None, email: str = "",
                 client_org_id: str | None = None) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "customer_id": customer_id,
        "client_org_id": client_org_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request) -> dict:
    """Authenticate the request and return the caller's *current* identity.

    The cookie proves who is calling; the users table decides what they may do
    right now. The signed claims are therefore only trusted for "sub", and
    role/customer_id/client_org_id are re-read from the database on every
    request — a JWT minted before a role change, a client-org move or a
    deactivation must not keep granting the access it was minted with. Those
    values also leave here as the X-Arckon-* headers /auth/verify hands to the
    customer vhosts, so a stale claim would propagate into every container."""
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401)
    try:
        claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401)
    try:
        current = revalidate_user(claims.get("sub"))
    except StaleSessionError:
        # Deleted or deactivated: fail closed, exactly as an expired token does.
        raise HTTPException(status_code=401)
    return {**claims, **current}


def require_super_admin(request: Request) -> dict:
    user = get_current_user(request)
    if user["role"] != "super_admin":
        raise HTTPException(status_code=403)
    return user

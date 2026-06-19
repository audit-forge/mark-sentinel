import os
import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import Request, HTTPException

def _load_secret_key() -> str:
    key = os.environ.get("SECRET_KEY", "")
    if not key:
        key_file = os.environ.get("SECRET_KEY_FILE", "")
        if key_file:
            try:
                import pathlib
                p = pathlib.Path(key_file)
                key = p.read_text().strip() if p.is_file() else ""
            except Exception:
                key = ""
    if not key:
        raise RuntimeError(
            "SECRET_KEY is not set. Provide it via SECRET_KEY env var "
            "or SECRET_KEY_FILE pointing to a file containing the key."
        )
    return key

SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_token(user_id: str, role: str, customer_id: str | None, email: str = "") -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "customer_id": customer_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request) -> dict:
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401)
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401)


def require_super_admin(request: Request) -> dict:
    user = get_current_user(request)
    if user["role"] != "super_admin":
        raise HTTPException(status_code=403)
    return user

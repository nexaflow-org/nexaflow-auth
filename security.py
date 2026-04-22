import os
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(user_id: str, email: str) -> str:
    issued_at = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "email": email,
        "iat": issued_at,
        "exp": issued_at + timedelta(minutes=int(os.getenv("JWT_EXP_MINUTES", "60"))),
    }
    return jwt.encode(
        payload,
        os.getenv("JWT_SECRET_KEY", "development-secret"),
        algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
    )


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            os.getenv("JWT_SECRET_KEY", "development-secret"),
            algorithms=[os.getenv("JWT_ALGORITHM", "HS256")],
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.") from exc


async def require_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_access_token(token)
    if not payload.get("sub") or not payload.get("email"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token.")
    return payload

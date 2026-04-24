import os
import time
from collections import defaultdict, deque
from typing import Annotated

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import Base, engine, get_db
from .models import UserAccount
from .schemas import (
    TokenResponse,
    TokenValidationRequest,
    TokenValidationResponse,
    UserCredentials,
    UserProfile,
)
from .security import create_access_token, decode_access_token, hash_password, require_user, verify_password

load_dotenv()

app = FastAPI(title=os.getenv("APP_NAME", "finagent-auth-service"))


def _allowed_origins() -> list[str]:
    origins: list[str] = []
    seen: set[str] = set()
    for raw_origin in os.getenv("ALLOWED_ORIGINS", "").replace("\n", ",").split(","):
        origin = raw_origin.strip().rstrip("/")
        if origin and origin not in seen:
            origins.append(origin)
            seen.add(origin)
    return origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

_request_log: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    client_ip = (
        request.headers.get("x-forwarded-for")
        or request.headers.get("x-real-ip")
        or request.client.host
        or "anonymous"
    ).split(",")[0].strip()
    now = time.time()
    window = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    limit = int(os.getenv("RATE_LIMIT_REQUESTS", "120"))
    bucket = _request_log[client_ip]
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")
    bucket.append(now)
    return await call_next(request)


@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/api/v1/auth/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/auth/signup", status_code=status.HTTP_201_CREATED)
async def signup(payload: UserCredentials, db: Annotated[AsyncSession, Depends(get_db)]) -> TokenResponse:
    existing_user = await db.scalar(select(UserAccount).where(UserAccount.email == payload.email.lower()))
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    user = UserAccount(email=payload.email.lower(), hashed_password=hash_password(payload.password))
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return TokenResponse(
        user_id=user.id,
        email=user.email,
        access_token=create_access_token(user.id, user.email),
    )


@app.post("/api/v1/auth/login")
async def login(payload: UserCredentials, db: Annotated[AsyncSession, Depends(get_db)]) -> TokenResponse:
    user = await db.scalar(select(UserAccount).where(UserAccount.email == payload.email.lower()))
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    return TokenResponse(
        user_id=user.id,
        email=user.email,
        access_token=create_access_token(user.id, user.email),
    )


@app.get("/api/v1/auth/me")
async def me(current_user: Annotated[dict, Depends(require_user)]) -> UserProfile:
    return UserProfile(user_id=current_user["sub"], email=current_user["email"])


@app.post("/api/v1/auth/token/validate")
async def validate_token(payload: TokenValidationRequest) -> TokenValidationResponse:
    decoded = decode_access_token(payload.token)
    return TokenValidationResponse(valid=True, user_id=decoded.get("sub"), email=decoded.get("email"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=os.getenv("APP_HOST", "0.0.0.0"), port=int(os.getenv("APP_PORT", "8001")), reload=True)

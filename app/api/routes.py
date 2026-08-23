from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    BrandResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.auth.provider import get_auth_provider
from app.core.config import get_settings
from app.db.models import Tenant, User
from app.db.session import get_db

router = APIRouter(tags=["identity"])
security = HTTPBearer(auto_error=False)
auth = get_auth_provider()
settings = get_settings()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.service_name}


@router.get("/brand", response_model=BrandResponse)
async def brand() -> BrandResponse:
    return BrandResponse(
        display_name=settings.brand_display_name,
        default_locale=settings.default_locale,
        logo_url=None,
    )


@router.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    existing = await db.scalar(select(User).where(User.email == body.email.lower()))
    if existing:
        raise HTTPException(status_code=409, detail="email_taken")

    tenant = Tenant(name=body.tenant_name)
    db.add(tenant)
    await db.flush()

    user = User(
        tenant_id=tenant.id,
        email=body.email.lower(),
        full_name=body.full_name,
        hashed_password=auth.hash_password(body.password),
        role="partner",
        locale=settings.default_locale,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = auth.create_access_token(
        user.id,
        {
            "email": user.email,
            "tenant_id": user.tenant_id,
            "role": user.role,
            "locale": user.locale,
        },
    )
    return TokenResponse(access_token=token)


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not auth.verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="user_inactive")

    token = auth.create_access_token(
        user.id,
        {
            "email": user.email,
            "tenant_id": user.tenant_id,
            "role": user.role,
            "locale": user.locale,
        },
    )
    return TokenResponse(access_token=token)


async def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(status_code=401, detail="not_authenticated")
    try:
        payload = auth.decode_token(creds.credentials)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid_token") from None
    user = await db.get(User, payload.get("sub"))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="invalid_token")
    return user


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(current_user)) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        locale=user.locale,
        tenant_id=user.tenant_id,
    )

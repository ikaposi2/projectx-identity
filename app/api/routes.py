from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    BrandResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserListItem,
    UserResponse,
)
from app.auth.provider import get_auth_provider
from app.core.config import get_settings
from app.db.models import Tenant, User
from app.db.session import get_db
from app.observability import audit

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
        audit(
            "user-create",
            outcome="failure",
            category=["iam", "authentication"],
            event_type=["user", "creation"],
            message="register failed: email taken",
            **{"user.email": body.email.lower()},
        )
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

    audit(
        "user-create",
        outcome="success",
        category=["iam", "authentication"],
        event_type=["user", "creation"],
        message="user registered",
        **{
            "user.id": user.id,
            "user.email": user.email,
            "user.name": user.full_name,
            "user.roles": [user.role],
            "organization.id": user.tenant_id,
            "organization.name": body.tenant_name,
        },
    )

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
        audit(
            "user-login",
            outcome="failure",
            category=["authentication"],
            event_type=["start"],
            message="login failed: invalid credentials",
            **{"user.email": body.email.lower()},
        )
        raise HTTPException(status_code=401, detail="invalid_credentials")
    if not user.is_active:
        audit(
            "user-login",
            outcome="failure",
            category=["authentication"],
            event_type=["start"],
            message="login failed: user inactive",
            **{
                "user.id": user.id,
                "user.email": user.email,
                "organization.id": user.tenant_id,
            },
        )
        raise HTTPException(status_code=403, detail="user_inactive")

    audit(
        "user-login",
        outcome="success",
        category=["authentication"],
        event_type=["start"],
        message="login succeeded",
        **{
            "user.id": user.id,
            "user.email": user.email,
            "user.name": user.full_name,
            "user.roles": [user.role],
            "organization.id": user.tenant_id,
        },
    )

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


@router.get("/users", response_model=list[UserListItem])
async def list_users(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list[UserListItem]:
    """Tenant directory for managers (resolve partner names in finance / admin)."""
    if user.role not in {"partner", "manager", "admin"}:
        raise HTTPException(status_code=403, detail="not_manager")
    rows = await db.scalars(
        select(User).where(User.tenant_id == user.tenant_id).order_by(User.full_name)
    )
    return [
        UserListItem(
            id=row.id,
            email=row.email,
            full_name=row.full_name,
            role=row.role,
            is_active=row.is_active,
        )
        for row in rows
    ]

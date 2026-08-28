import secrets
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    AuthConfigResponse,
    BrandResponse,
    LoginRequest,
    OidcCallbackRequest,
    RegisterRequest,
    TokenResponse,
    UserListItem,
    UserResponse,
)
from app.auth import oidc as oidc_auth
from app.auth.provider import get_auth_provider
from app.core.config import get_settings
from app.db.models import Tenant, User
from app.db.session import get_db
from app.observability import audit
from app.observability.audit import set_audit_session_id

router = APIRouter(tags=["identity"])
security = HTTPBearer(auto_error=False)
auth = get_auth_provider()
settings = get_settings()


def _issue_token(user: User, *, session_id: str | None = None) -> tuple[str, str]:
    jti = session_id or str(uuid4())
    token = auth.create_access_token(
        user.id,
        {
            "jti": jti,
            "email": user.email,
            "tenant_id": user.tenant_id,
            "role": user.role,
            "locale": user.locale,
        },
    )
    return token, jti


def _oidc_enabled() -> bool:
    return settings.auth_mode.lower().strip() == "oidc"


def _oidc_audit_fields(identity: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "auth.method": "oidc",
        "identity.provider": "keycloak",
    }
    if identity:
        if identity.get("sub"):
            fields["user.oidc.sub"] = identity["sub"]
        if identity.get("email"):
            fields["user.email"] = identity["email"]
        if identity.get("groups"):
            fields["identity.groups"] = identity["groups"]
        if identity.get("role"):
            fields["user.roles"] = [identity["role"]]
    fields.update(extra)
    return fields


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


@router.get("/auth/config", response_model=AuthConfigResponse)
async def auth_config() -> AuthConfigResponse:
    try:
        cfg = await oidc_auth.public_auth_config()
    except Exception as exc:
        if _oidc_enabled():
            raise HTTPException(status_code=503, detail="oidc_unavailable") from exc
        return AuthConfigResponse(auth_mode=settings.auth_mode.lower().strip())
    return AuthConfigResponse(auth_mode=cfg["auth_mode"], oidc=cfg.get("oidc"))


@router.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    if _oidc_enabled():
        raise HTTPException(status_code=403, detail="registration_disabled")
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

    token, session_id = _issue_token(user)
    set_audit_session_id(session_id)
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
            "session.id": session_id,
        },
    )
    return TokenResponse(access_token=token)


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    if _oidc_enabled():
        raise HTTPException(status_code=403, detail="use_oidc")
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

    session_id = str(uuid4())
    set_audit_session_id(session_id)
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
            "session.id": session_id,
        },
    )

    token, _ = _issue_token(user, session_id=session_id)
    return TokenResponse(access_token=token)


async def _ensure_tenant(db: AsyncSession) -> Tenant:
    tenant = await db.scalar(
        select(Tenant).where(Tenant.name == settings.oidc_default_tenant)
    )
    if tenant:
        return tenant
    tenant = await db.scalar(select(Tenant).order_by(Tenant.created_at))
    if tenant:
        return tenant
    tenant = Tenant(name=settings.oidc_default_tenant)
    db.add(tenant)
    await db.flush()
    return tenant


@router.post("/auth/oidc/callback", response_model=TokenResponse)
async def oidc_callback(
    body: OidcCallbackRequest, db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    if not _oidc_enabled():
        raise HTTPException(status_code=403, detail="oidc_disabled")
    try:
        identity = await oidc_auth.exchange_code(
            code=body.code,
            code_verifier=body.code_verifier,
            redirect_uri=body.redirect_uri,
        )
    except ValueError as exc:
        audit(
            "user-login",
            outcome="failure",
            category=["authentication"],
            event_type=["start"],
            message=f"oidc login failed: {exc}",
            **_oidc_audit_fields(),
        )
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        audit(
            "user-login",
            outcome="failure",
            category=["authentication"],
            event_type=["start"],
            message="oidc login failed: exchange error",
            **_oidc_audit_fields(),
        )
        raise HTTPException(status_code=401, detail="oidc_exchange_failed") from exc

    sub = identity["sub"]
    email = identity["email"]
    user = None
    if sub:
        user = await db.scalar(select(User).where(User.oidc_sub == sub))
    if user is None:
        user = await db.scalar(select(User).where(User.email == email))
    created = False
    if user is None:
        tenant = await _ensure_tenant(db)
        user = User(
            tenant_id=tenant.id,
            email=email,
            full_name=identity["full_name"],
            hashed_password=auth.hash_password(secrets.token_urlsafe(32)),
            oidc_sub=sub or None,
            role=identity["role"],
            locale=settings.default_locale,
        )
        db.add(user)
        created = True
    else:
        if sub and not user.oidc_sub:
            user.oidc_sub = sub
        user.full_name = identity["full_name"] or user.full_name
        user.role = identity["role"]
        if user.email != email:
            user.email = email
    if not user.is_active:
        audit(
            "user-login",
            outcome="failure",
            category=["authentication"],
            event_type=["start"],
            message="oidc login failed: user inactive",
            **_oidc_audit_fields(identity, **{"user.id": user.id}),
        )
        raise HTTPException(status_code=403, detail="user_inactive")

    await db.commit()
    await db.refresh(user)

    session_id = str(uuid4())
    set_audit_session_id(session_id)
    audit(
        "user-create" if created else "user-login",
        outcome="success",
        category=["authentication", "iam"] if created else ["authentication"],
        event_type=["user", "creation"] if created else ["start"],
        message="oidc user provisioned" if created else "oidc login succeeded",
        **_oidc_audit_fields(
            identity,
            **{
                "user.id": user.id,
                "user.name": user.full_name,
                "organization.id": user.tenant_id,
                "session.id": session_id,
            },
        ),
    )
    token, _ = _issue_token(user, session_id=session_id)
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
    jti = payload.get("jti")
    if jti:
        set_audit_session_id(str(jti))
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

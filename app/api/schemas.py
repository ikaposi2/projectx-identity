from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=1, max_length=200)
    tenant_name: str = Field(default="Default", max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class OidcCallbackRequest(BaseModel):
    code: str = Field(min_length=1)
    code_verifier: str = Field(min_length=43, max_length=128)
    redirect_uri: str = Field(min_length=1, max_length=500)


class AuthConfigResponse(BaseModel):
    auth_mode: str
    oidc: dict | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    locale: str
    tenant_id: str


class UserListItem(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool


class BrandResponse(BaseModel):
    display_name: str
    default_locale: str
    logo_url: str | None = None

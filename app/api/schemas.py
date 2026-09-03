from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=1, max_length=200)
    tenant_name: str = Field(default="Default", max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CustomerRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=1, max_length=200)
    company_name: str = Field(min_length=1, max_length=200)
    contact_phone: str | None = Field(default=None, max_length=40)
    address_line1: str | None = Field(default=None, max_length=200)
    address_line2: str | None = Field(default=None, max_length=200)
    postal_code: str | None = Field(default=None, max_length=32)
    city: str | None = Field(default=None, max_length=120)
    country: str | None = Field(default=None, max_length=120)
    vat_id: str | None = Field(default=None, max_length=64)


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
    customer_id: str | None = None


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

from datetime import datetime, timedelta, timezone
from typing import Protocol

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


class AuthProvider(Protocol):
    """Swap LocalAuthProvider for OidcAuthProvider (Keycloak) later."""

    def hash_password(self, password: str) -> str: ...
    def verify_password(self, plain: str, hashed: str) -> bool: ...
    def create_access_token(self, subject: str, claims: dict) -> str: ...
    def decode_token(self, token: str) -> dict: ...


class LocalAuthProvider:
    def hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        return pwd_context.verify(plain, hashed)

    def create_access_token(self, subject: str, claims: dict) -> str:
        payload = {
            "sub": subject,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=settings.access_token_expire_minutes),
            **claims,
        }
        return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def decode_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        except JWTError as exc:
            raise ValueError("invalid_token") from exc


def get_auth_provider() -> AuthProvider:
    return LocalAuthProvider()

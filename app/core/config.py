from functools import lru_cache

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    service_name: str = "projectX-identity"
    environment: str = "dev"
    database_url: str | None = None
    # Prefer PX_DB_* — Kubernetes injects POSTGRES_PORT=tcp://... for Service "postgres"
    db_user: str = Field(default="projectx", validation_alias="PX_DB_USER")
    db_password: str = Field(default="change-me-now", validation_alias="PX_DB_PASSWORD")
    db_host: str = Field(default="postgres", validation_alias="PX_DB_HOST")
    db_port: int = Field(default=5432, validation_alias="PX_DB_PORT")
    db_name: str = Field(default="identity", validation_alias="PX_DB_NAME")
    jwt_secret: str = "dev-only-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    auth_mode: str = Field(default="local", validation_alias="AUTH_MODE")
    oidc_issuer: str = Field(
        default="https://auth.apps.cloud.kaposi.net/realms/kaposi",
        validation_alias="OIDC_ISSUER",
    )
    oidc_client_id: str = Field(default="projectx-web", validation_alias="OIDC_CLIENT_ID")
    oidc_redirect_uris: str = Field(
        default="https://projectx.apps.cloud.kaposi.net/auth/callback,http://localhost:5173/auth/callback",
        validation_alias="OIDC_REDIRECT_URIS",
    )
    oidc_default_tenant: str = Field(default="Kaposi", validation_alias="OIDC_DEFAULT_TENANT")
    otel_exporter_otlp_endpoint: str | None = None
    brand_display_name: str = Field(default="Platform", validation_alias="BRAND_DISPLAY_NAME")
    default_locale: str = "nl"
    cors_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:5174,http://127.0.0.1:5174"
    )
    customer_service_url: str = Field(
        default="http://localhost:8005",
        validation_alias="CUSTOMER_SERVICE_URL",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+asyncpg://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()

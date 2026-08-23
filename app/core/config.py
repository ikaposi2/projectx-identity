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
    otel_exporter_otlp_endpoint: str | None = None
    brand_display_name: str = "Platform"
    default_locale: str = "nl"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

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

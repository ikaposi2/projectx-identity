# projectX-identity

Identity microservice: authentication, users, roles, tenant context, brand config.

- **Auth:** `AUTH_MODE=local` (email/password) or `AUTH_MODE=oidc` (Keycloak PKCE; Identity still issues platform JWTs)
- **Prepared for:** Keycloak via OIDC (ADR 0003 / ADR 0019)
- **DB:** `identity` database on in-cluster Postgres

## Local run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

## Env

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | sqlite for local | Postgres URL in cluster |
| `AUTH_MODE` | `local` | `local` or `oidc` (staff); customer portal login is always local |
| `OIDC_ISSUER` | Keycloak kaposi realm | used when `AUTH_MODE=oidc` |
| `OIDC_CLIENT_ID` | `projectx-web` | public PKCE client |
| `CUSTOMER_SERVICE_URL` | `http://localhost:8005` | Portal register creates Customer |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | | collector URL |
| `SERVICE_NAME` | `projectX-identity` | OTel resource |

## Customer portal auth

| Method | Path | Notes |
|--------|------|-------|
| POST | `/auth/customer/register` | Creates Customer + User(`role=customer`); works with staff OIDC |
| POST | `/auth/customer/login` | Local email/password; JWT includes `customer_id` |
| GET | `/me` | Includes `customer_id` when present |

See [ADR 0021](../projectX-docs/docs/adr/0021-customer-portal-auth.md).

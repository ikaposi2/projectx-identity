# projectX-identity

Identity microservice: authentication, users, roles, tenant context, brand config.

- **Auth (MVP):** local email/password + JWT
- **Prepared for:** Keycloak via OIDC provider swap (see ADR 0003)
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
| `JWT_SECRET` | dev-only | signing key |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | | collector URL |
| `SERVICE_NAME` | `projectX-identity` | OTel resource |

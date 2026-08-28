"""Keycloak OIDC code exchange → Identity user + platform JWT claims."""

from __future__ import annotations

import time
from typing import Any

import httpx
from jose import JWTError, jwt

from app.core.config import get_settings

_discovery: dict[str, Any] | None = None
_discovery_at = 0.0
_jwks: dict[str, Any] | None = None
_jwks_at = 0.0
_CACHE_TTL = 600.0

GROUP_ROLE_PRIORITY = (
    ("platform-admins", "admin"),
    ("platform-consultants", "manager"),
)
_ROLE_RANK = {"admin": 3, "manager": 2, "partner": 1}


def map_groups_to_role(groups: list[str]) -> str:
    names = {g.strip("/").split("/")[-1] for g in groups if g}
    role = "partner"
    for group, mapped in GROUP_ROLE_PRIORITY:
        if group in names and _ROLE_RANK[mapped] > _ROLE_RANK[role]:
            role = mapped
    return role


def allowed_redirect_uris() -> set[str]:
    return {u.strip() for u in get_settings().oidc_redirect_uris.split(",") if u.strip()}


async def _get_discovery() -> dict[str, Any]:
    global _discovery, _discovery_at
    now = time.monotonic()
    if _discovery and now - _discovery_at < _CACHE_TTL:
        return _discovery
    issuer = get_settings().oidc_issuer.rstrip("/")
    url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        _discovery = resp.json()
        _discovery_at = now
    return _discovery


async def _get_jwks() -> dict[str, Any]:
    global _jwks, _jwks_at
    now = time.monotonic()
    if _jwks and now - _jwks_at < _CACHE_TTL:
        return _jwks
    discovery = await _get_discovery()
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(discovery["jwks_uri"])
        resp.raise_for_status()
        _jwks = resp.json()
        _jwks_at = now
    return _jwks


async def public_auth_config() -> dict[str, Any]:
    settings = get_settings()
    mode = settings.auth_mode.lower().strip()
    cfg: dict[str, Any] = {"auth_mode": mode}
    if mode == "oidc":
        discovery = await _get_discovery()
        cfg["oidc"] = {
            "issuer": settings.oidc_issuer.rstrip("/"),
            "client_id": settings.oidc_client_id,
            "authorization_endpoint": discovery["authorization_endpoint"],
            "end_session_endpoint": discovery.get("end_session_endpoint"),
        }
    return cfg


def _decode_id_token(id_token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        raise ValueError("unknown_kid")
    try:
        return jwt.decode(
            id_token,
            key,
            algorithms=[header.get("alg") or "RS256"],
            audience=settings.oidc_client_id,
            issuer=settings.oidc_issuer.rstrip("/"),
            options={"verify_at_hash": False},
        )
    except JWTError as exc:
        raise ValueError("invalid_id_token") from exc


def _groups_from_claims(*claim_sets: dict[str, Any]) -> list[str]:
    for claims in claim_sets:
        raw = claims.get("groups")
        if isinstance(raw, list):
            return [str(g) for g in raw]
        if isinstance(raw, str) and raw:
            return [raw]
    return []


async def exchange_code(*, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
    if redirect_uri not in allowed_redirect_uris():
        raise ValueError("invalid_redirect_uri")
    settings = get_settings()
    discovery = await _get_discovery()
    async with httpx.AsyncClient(timeout=15.0) as client:
        token_resp = await client.post(
            discovery["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": settings.oidc_client_id,
                "code_verifier": code_verifier,
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code >= 400:
            raise ValueError("oidc_exchange_failed")
        tokens = token_resp.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise ValueError("missing_id_token")
        jwks = await _get_jwks()
        claims = _decode_id_token(id_token, jwks)
        extra: dict[str, Any] = {}
        access = tokens.get("access_token")
        if access:
            extra = jwt.get_unverified_claims(access)
        userinfo: dict[str, Any] = {}
        userinfo_url = discovery.get("userinfo_endpoint")
        if userinfo_url and access:
            ui = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access}"},
            )
            if ui.status_code == 200:
                userinfo = ui.json()
    groups = _groups_from_claims(claims, extra, userinfo)
    email = (claims.get("email") or userinfo.get("email") or "").strip().lower()
    if not email:
        raise ValueError("email_required")
    name = (
        (claims.get("name") or userinfo.get("name") or "").strip()
        or (claims.get("preferred_username") or email.split("@")[0])
    )
    return {
        "sub": str(claims.get("sub") or ""),
        "email": email,
        "full_name": str(name)[:200],
        "groups": groups,
        "role": map_groups_to_role(groups),
    }

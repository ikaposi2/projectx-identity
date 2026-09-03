from __future__ import annotations

from typing import Any

import httpx

from app.core.config import get_settings

settings = get_settings()


class CustomerClientError(Exception):
    def __init__(self, detail: str, status_code: int | None = None):
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


async def create_portal_customer(*, access_token: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"{settings.customer_service_url.rstrip('/')}/customers"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise CustomerClientError("customer_unavailable") from exc
    if res.status_code == 409:
        raise CustomerClientError("name_exists", status_code=409)
    if res.status_code >= 400:
        detail = "customer_create_failed"
        try:
            body = res.json()
            if isinstance(body, dict) and body.get("detail"):
                detail = str(body["detail"])
        except Exception:
            pass
        raise CustomerClientError(detail, status_code=res.status_code)
    return res.json()

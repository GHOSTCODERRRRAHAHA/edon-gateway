"""MAG client helpers for gateway enforcement."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import requests

from .config import config
from .persistence import get_db

LOGGER = logging.getLogger(__name__)


def mag_enabled_for_tenant(tenant_id: Optional[str]) -> bool:
    if config.MAG_ENABLED:
        return True
    if not tenant_id:
        return False
    try:
        db = get_db()
        return db.is_mag_enabled(tenant_id)
    except Exception:
        return False


def fetch_decision_bundle(decision_id: str) -> Optional[Dict[str, Any]]:
    if not decision_id:
        return None
    url = f"{config.MAG_URL}/mag/ledger/decisions/{decision_id}"
    timeout_s = float("5")
    try:
        resp = requests.get(url, timeout=timeout_s)
    except Exception as exc:
        LOGGER.warning("MAG decision lookup failed: %s", exc)
        return None
    if resp.status_code == 404:
        return None
    if not resp.ok:
        LOGGER.warning("MAG decision lookup error (%s): %s", resp.status_code, resp.text)
        return None
    try:
        payload = resp.json()
    except Exception:
        return None
    if isinstance(payload, dict) and payload.get("ok") and payload.get("decision"):
        return payload.get("decision")
    return payload if isinstance(payload, dict) else None


def extract_decision_verdict(decision_bundle: Dict[str, Any]) -> Optional[str]:
    if not decision_bundle:
        return None
    if isinstance(decision_bundle.get("decision"), dict):
        decision = decision_bundle.get("decision") or {}
        verdict = decision.get("decision") or decision.get("verdict")
        return verdict.lower() if isinstance(verdict, str) else None
    verdict = decision_bundle.get("decision") or decision_bundle.get("verdict")
    return verdict.lower() if isinstance(verdict, str) else None


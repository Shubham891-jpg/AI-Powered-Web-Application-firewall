"""
Rule Management API Endpoints (Phase 9).
Provides endpoints for listing active rules, toggling state, and updating severity scores.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.detection.detector import request_detector

router = APIRouter(prefix="/rules", tags=["Rules"])


class RuleUpdatePayload(BaseModel):
    enabled: Optional[bool] = None
    score: Optional[int] = None


@router.get("")
async def list_rules():
    """Lists all loaded detection rules with active status and severity score."""
    rules = list(request_detector.registry._rules.values())
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "category": r.category,
            "score": r.score,
            "enabled": r.enabled,
        }
        for r in rules
    ]


@router.patch("/{rule_id}")
async def update_rule(rule_id: str, payload: RuleUpdatePayload):
    """Toggles active state or updates severity score for a detection rule."""
    rule = request_detector.registry.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    if payload.enabled is not None:
        rule.enabled = payload.enabled

    if payload.score is not None:
        rule.score = max(0, min(100, payload.score))

    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "category": rule.category,
        "score": rule.score,
        "enabled": rule.enabled,
    }

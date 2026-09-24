"""Pydantic schemas for the audit API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .bidi import RiskLevel


class AuditRequest(BaseModel):
    text: str = Field(..., description="Text to audit. Sent verbatim; never rewritten.")
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional source file name for later lookup.",
    )


class AuditCreated(BaseModel):
    id: int
    risk_level: RiskLevel
    stored: bool = True
    result: dict


class CompareRequest(BaseModel):
    before_id: int = Field(
        ..., ge=1, description="ID of the earlier audit record (baseline)."
    )
    after_id: int = Field(
        ..., ge=1, description="ID of the later audit record (regression)."
    )


class DiffAuditRequest(BaseModel):
    diff: str = Field(
        ...,
        description=(
            "Unified diff text (multi-file, multi-hunk). Only added lines "
            "(those starting with '+') are audited; headers, removed and "
            "context lines are ignored."
        ),
    )


class JsonAuditRequest(BaseModel):
    document: str = Field(
        ...,
        description=(
            "Raw JSON document text. Parsed strictly (RFC 8259): duplicate "
            "object keys and malformed input are rejected with 422. Every "
            "string value (object values and array elements, never object "
            "keys) is audited for bidi controls."
        ),
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description=(
            "Optional document name. Stored records are named "
            "'<filename>#<json-pointer>' ('#<json-pointer>' when omitted)."
        ),
    )

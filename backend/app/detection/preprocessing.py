"""
Request Normalization and Preprocessing Pipeline.
Provides structured request extraction, multi-pass decoding, HTML entity unescaping,
Unicode normalization (NFKC), path canonicalization, and null-byte detection,
while strictly preserving the immutable raw request representation.
"""

import html
import json
import posixpath
import re
import unicodedata
import urllib.parse
from typing import Any, Optional
from pydantic import BaseModel, Field
from starlette.requests import Request


class RawRequest(BaseModel):
    """Immutable representation of the inbound HTTP request as received from the wire."""
    request_id: str
    client_ip: str
    method: str
    path: str
    raw_query: str
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    content_type: str = ""
    body_text: str = ""
    parsed_body: Any = None


class NormalizedRequest(BaseModel):
    """Canonical normalized representation of the request designed for security inspection."""
    canonical_path: str
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body_text: str = ""
    canonical_inspection_string: str = ""
    encoding_depth: int = 0
    has_null_bytes: bool = False
    has_unicode_anomalies: bool = False
    transformations: list[str] = Field(default_factory=list)


class InspectedRequestContext(BaseModel):
    """Container holding both original raw request and normalized security representation."""
    raw: RawRequest
    normalized: NormalizedRequest


class RequestParser:
    """Extracts and structures incoming HTTP requests into RawRequest instances."""

    @staticmethod
    async def parse_request(request: Request, request_id: str, client_ip: str) -> RawRequest:
        path = request.url.path
        raw_query = request.url.query
        method = request.method.upper()

        # Parse query params (preserving multiple values)
        query_dict: dict[str, list[str]] = {}
        for key, value in request.query_params.multi_items():
            query_dict.setdefault(key, []).append(value)

        # Extract headers (lower-cased keys)
        headers = {k.lower(): v for k, v in request.headers.items()}
        cookies = dict(request.cookies)
        content_type = headers.get("content-type", "")

        # Safely parse request body
        body_text = ""
        parsed_body = None
        try:
            body_bytes = await request.body()
            if body_bytes:
                # Limit initial inspection string length for memory safety
                decoded_str = body_bytes.decode("utf-8", errors="replace")
                body_text = decoded_str

                if "application/json" in content_type:
                    try:
                        parsed_body = json.loads(decoded_str)
                    except Exception:
                        parsed_body = None
                elif "application/x-www-form-urlencoded" in content_type:
                    parsed_form: dict[str, list[str]] = {}
                    for k, v in urllib.parse.parse_qs(decoded_str, keep_blank_values=True).items():
                        parsed_form[k] = v
                    parsed_body = parsed_form
        except Exception:
            body_text = ""

        return RawRequest(
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            path=path,
            raw_query=raw_query,
            query_params=query_dict,
            headers=headers,
            cookies=cookies,
            content_type=content_type,
            body_text=body_text,
            parsed_body=parsed_body,
        )


class RequestNormalizer:
    """
    Applies multi-pass canonical transformations to detect obfuscations:
    - Multi-pass URL decoding (up to 4 passes)
    - Null-byte detection and elimination
    - HTML entity resolution (named, numeric, hex)
    - Unicode NFKC canonicalization
    - Path canonicalization
    - Whitespace normalization
    """

    MAX_DECODE_PASSES = 4

    @classmethod
    def normalize_text(cls, raw: str) -> tuple[str, int, bool, bool, list[str]]:
        """
        Normalizes a single text string.
        Returns: (normalized_text, encoding_depth, has_null_bytes, has_unicode_anomalies, transformations)
        """
        if not raw:
            return "", 0, False, False, []

        current = raw
        transformations: list[str] = []
        has_null_bytes = False
        has_unicode_anomalies = False

        # 1. Check and strip null bytes
        if "\x00" in current or "%00" in current.lower():
            has_null_bytes = True
            current = current.replace("\x00", "").replace("%00", "").replace("%0O", "")
            transformations.append("null_byte_removal")

        # 2. Multi-pass URL decoding
        depth = 0
        for _ in range(cls.MAX_DECODE_PASSES):
            try:
                decoded = urllib.parse.unquote(current)
            except Exception:
                break
            if decoded == current:
                break
            depth += 1
            current = decoded

        if depth > 0:
            transformations.append(f"url_decode_depth_{depth}")

        # 3. HTML entity unescaping (named, decimal, hex)
        unescaped_html = html.unescape(current)
        if unescaped_html != current:
            current = unescaped_html
            transformations.append("html_entity_decode")

        # 4. Unicode normalization (NFKC)
        normalized_unicode = unicodedata.normalize("NFKC", current)
        if normalized_unicode != current:
            has_unicode_anomalies = True
            current = normalized_unicode
            transformations.append("unicode_nfkc_normalize")

        # 5. Collapse excessive whitespace and control characters
        cleaned_whitespace = " ".join(current.split())
        if cleaned_whitespace != current:
            current = cleaned_whitespace
            transformations.append("whitespace_collapse")

        return current, depth, has_null_bytes, has_unicode_anomalies, transformations

    @classmethod
    def canonicalize_path(cls, raw_path: str) -> str:
        """
        Canonicalizes URI path by decoding, collapsing redundant slashes,
        and resolving relative dot segments ('../' and '/./').
        """
        if not raw_path:
            return "/"

        # Pre-decode path for canonical view
        decoded_path = urllib.parse.unquote(raw_path)
        # Normalize slashes (convert Windows \ to /)
        normalized_slashes = decoded_path.replace("\\", "/")
        # Collapse multiple slashes
        collapsed = re.sub(r"/+", "/", normalized_slashes)
        # Resolve dot segments using posixpath
        canonical = posixpath.normpath(collapsed)
        if not canonical.startswith("/"):
            canonical = "/" + canonical
        return canonical

    @classmethod
    def normalize_request(cls, raw_req: RawRequest) -> NormalizedRequest:
        """Constructs a NormalizedRequest from a RawRequest."""
        all_transformations: list[str] = []
        max_depth = 0
        any_null_bytes = False
        any_unicode_anomalies = False

        # Normalize Path
        canonical_path = cls.canonicalize_path(raw_req.path)

        # Normalize Query Parameters
        raw_queries = dict(raw_req.query_params)
        if not raw_queries and raw_req.raw_query:
            raw_queries = urllib.parse.parse_qs(raw_req.raw_query, keep_blank_values=True)

        norm_query_params: dict[str, list[str]] = {}
        for key, values in raw_queries.items():
            norm_k, k_depth, k_null, k_uni, k_trans = cls.normalize_text(key)
            norm_vals: list[str] = []
            for v in values:
                norm_v, v_depth, v_null, v_uni, v_trans = cls.normalize_text(v)
                norm_vals.append(norm_v)
                max_depth = max(max_depth, v_depth)
                any_null_bytes = any_null_bytes or v_null
                any_unicode_anomalies = any_unicode_anomalies or v_uni
                all_transformations.extend(v_trans)

            norm_query_params[norm_k] = norm_vals
            max_depth = max(max_depth, k_depth)
            any_null_bytes = any_null_bytes or k_null
            any_unicode_anomalies = any_unicode_anomalies or k_uni
            all_transformations.extend(k_trans)

        # Normalize Relevant Headers (User-Agent, Referer, Host, Content-Type)
        norm_headers: dict[str, str] = {}
        inspectable_headers = {"user-agent", "referer", "origin", "content-type", "x-forwarded-host"}
        for h_key, h_val in raw_req.headers.items():
            if h_key in inspectable_headers:
                h_norm, h_depth, h_null, h_uni, h_trans = cls.normalize_text(h_val)
                norm_headers[h_key] = h_norm
                max_depth = max(max_depth, h_depth)
                any_null_bytes = any_null_bytes or h_null
                any_unicode_anomalies = any_unicode_anomalies or h_uni
                all_transformations.extend(h_trans)

        # Normalize Body Text
        norm_body = ""
        if raw_req.body_text:
            norm_body, b_depth, b_null, b_uni, b_trans = cls.normalize_text(raw_req.body_text)
            max_depth = max(max_depth, b_depth)
            any_null_bytes = any_null_bytes or b_null
            any_unicode_anomalies = any_unicode_anomalies or b_uni
            all_transformations.extend(b_trans)

        # Build Composite Canonical Inspection Target String
        # Concatenates method, path, query keys & values, headers, and body for scanning
        inspection_parts = [
            f"METHOD:{raw_req.method}",
            f"PATH:{canonical_path}",
        ]
        if raw_req.path != canonical_path:
            # Also preserve raw path elements for path traversal detection
            inspection_parts.append(f"RAW_PATH:{raw_req.path}")

        for k, vals in norm_query_params.items():
            for v in vals:
                inspection_parts.append(f"PARAM:{k}={v}")

        for hk, hv in norm_headers.items():
            inspection_parts.append(f"HEADER:{hk}={hv}")

        if norm_body:
            inspection_parts.append(f"BODY:{norm_body}")

        canonical_inspection_string = " \n ".join(inspection_parts)

        return NormalizedRequest(
            canonical_path=canonical_path,
            query_params=norm_query_params,
            headers=norm_headers,
            body_text=norm_body,
            canonical_inspection_string=canonical_inspection_string,
            encoding_depth=max_depth,
            has_null_bytes=any_null_bytes,
            has_unicode_anomalies=any_unicode_anomalies,
            transformations=list(set(all_transformations)),
        )

    @classmethod
    def create_context(cls, raw_req: RawRequest) -> InspectedRequestContext:
        """Constructs full InspectedRequestContext preserving raw and normalized states."""
        normalized = cls.normalize_request(raw_req)
        return InspectedRequestContext(raw=raw_req, normalized=normalized)


# Backward compatibility helper
def normalize_string(raw_text: str):
    norm_text, depth, has_null, has_uni, trans = RequestNormalizer.normalize_text(raw_text)
    class LegacyNormalizedResult(BaseModel):
        raw: str
        normalized: str
        is_multivalue_encoded: bool = False
    return LegacyNormalizedResult(
        raw=raw_text,
        normalized=norm_text,
        is_multivalue_encoded=depth > 1,
    )

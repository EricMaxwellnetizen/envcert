"""Strict OCI image-reference digest handling.

Envicert must never bind a mutable tag or a malformed digest into a report or
attestation.  These helpers are shared by `check`, `attest` and
`verify-attestation` so the same rule is enforced everywhere.
"""
from __future__ import annotations

import re

from envicert.core.errors import ConfigError

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")


def normalize_digest(value: str, where: str = "digest") -> str:
    """Return a lowercase `sha256:<64 hex>` digest or raise ConfigError."""
    if not isinstance(value, str):
        raise ConfigError(f"invalid {where} {value!r}: expected sha256:<64 lowercase hex>")
    digest = value.strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ConfigError(
            f"invalid {where} {value!r}: expected sha256:<64 lowercase hex>; "
            "refusing to bind a malformed digest"
        )
    return digest


def parse_image_digest(reference: str, where: str = "--image") -> tuple[str, str]:
    """Split `name@sha256:<64 hex>` into `(name, digest)`.

    Tags are rejected: an attestation or report must bind immutable content.
    """
    if not isinstance(reference, str) or "@" not in reference:
        raise ConfigError(
            f"{where} must be an immutable reference name@sha256:<64 hex>, got {reference!r}"
        )
    name, _, digest = reference.rpartition("@")
    if not name:
        raise ConfigError(f"{where} has an empty image name: {reference!r}")
    return name, normalize_digest(digest, f"digest in {where}")


def image_digest_from_reference(reference: str, where: str = "--image") -> str | None:
    """Return the digest embedded in an image reference, or None for a tag."""
    if "@" not in reference:
        return None
    _name, digest = parse_image_digest(reference, where)
    return digest

"""Audit Evidence Package export and re-import verification.

Builds deterministic JSON packages from hash-chained audit JSONL files without
adding raw tool parameters or payload content. The package is intended as the
first Lliam-GOV AEP export surface for ISO 42001 / CMMC evidence collection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from lliam_gov.security.audit_logger import (
    AuditChainError,
    canonical_json,
    sha256_text,
    verify_audit_chain,
)


AEP_SCHEMA = "lliam-gov.audit.aep"
AEP_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AEPSourceVerification:
    """Verification summary for one exported audit source."""

    path: str
    record_count: int
    last_hash: str


@dataclass(frozen=True)
class AEPVerification:
    """Verification summary for an AEP package."""

    record_count: int
    sources: tuple[AEPSourceVerification, ...]


def build_aep_export(
    audit_paths: Sequence[str | Path],
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a deterministic AEP JSON object from audit JSONL files."""

    generated = _utc(generated_at)
    records: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []

    for audit_path_raw in audit_paths:
        audit_path = Path(audit_path_raw)
        verification = verify_audit_chain(audit_path)
        source_records = _read_audit_records(audit_path)
        if verification.record_count != len(source_records):
            raise AuditChainError(
                f"record count mismatch for {audit_path}: "
                f"chain={verification.record_count}, parsed={len(source_records)}"
            )

        first_index = len(records)
        records.extend(source_records)
        last_index = len(records) - 1
        timestamps = [
            r.get("timestamp_ms_utc")
            for r in source_records
            if isinstance(r.get("timestamp_ms_utc"), int)
        ]
        sources.append({
            "path": str(audit_path),
            "record_count": len(source_records),
            "first_record_index": first_index,
            "last_record_index": last_index,
            "first_timestamp_ms_utc": min(timestamps) if timestamps else None,
            "last_timestamp_ms_utc": max(timestamps) if timestamps else None,
            "last_hash": verification.last_hash,
        })

    return {
        "schema": AEP_SCHEMA,
        "schema_version": AEP_SCHEMA_VERSION,
        "generated_at_ms_utc": int(generated.timestamp() * 1000),
        "source_count": len(sources),
        "record_count": len(records),
        "sources": sources,
        "records": records,
    }


def write_aep_export(
    audit_paths: Sequence[str | Path],
    output_path: str | Path,
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build and write an AEP package as canonical JSON."""

    package = build_aep_export(audit_paths, generated_at=generated_at)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(canonical_json(package) + "\n", encoding="utf-8")
    return package


def verify_aep_export(
    package_or_path: Mapping[str, Any] | str | Path,
) -> AEPVerification:
    """Re-import an AEP package and verify embedded audit-chain continuity."""

    package = _load_package(package_or_path)
    _require(package.get("schema") == AEP_SCHEMA, "unsupported AEP schema")
    _require(
        package.get("schema_version") == AEP_SCHEMA_VERSION,
        "unsupported AEP schema_version",
    )
    records = package.get("records")
    sources = package.get("sources")
    _require(isinstance(records, list), "AEP records must be a list")
    _require(isinstance(sources, list), "AEP sources must be a list")
    _require(package.get("record_count") == len(records), "AEP record_count mismatch")
    _require(package.get("source_count") == len(sources), "AEP source_count mismatch")

    verified_sources: list[AEPSourceVerification] = []
    for source in sources:
        _require(isinstance(source, dict), "AEP source must be an object")
        first = source.get("first_record_index")
        last = source.get("last_record_index")
        count = source.get("record_count")
        _require(isinstance(first, int), "AEP source first_record_index must be int")
        _require(isinstance(last, int), "AEP source last_record_index must be int")
        _require(isinstance(count, int), "AEP source record_count must be int")
        _require(count == last - first + 1, "AEP source record_count range mismatch")
        _require(0 <= first <= last < len(records), "AEP source record range invalid")

        last_hash = _verify_record_slice(records[first : last + 1])
        expected_hash = source.get("last_hash")
        if last_hash != expected_hash:
            raise AuditChainError(
                "last_hash mismatch for AEP source "
                f"{source.get('path')}: expected {expected_hash}, got {last_hash}"
            )
        verified_sources.append(
            AEPSourceVerification(
                path=str(source.get("path")),
                record_count=count,
                last_hash=last_hash,
            )
        )

    return AEPVerification(
        record_count=len(records),
        sources=tuple(verified_sources),
    )


def _read_audit_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuditChainError(f"cannot read audit log {path}: {exc}") from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditChainError(
                f"invalid JSON at {path}:{line_number}: {exc}"
            ) from exc
        _require(isinstance(record, dict), f"audit record is not an object at {path}")
        records.append(record)
    return records


def _verify_record_slice(records: Sequence[dict[str, Any]]) -> str:
    previous_hash = "sha256:" + ("0" * 64)
    for index, record in enumerate(records):
        observed_prev = record.get("prev_hash")
        if index == 0 and observed_prev != previous_hash:
            raise AuditChainError("genesis prev_hash mismatch in AEP records")
        if observed_prev != previous_hash:
            raise AuditChainError(
                f"prev_hash mismatch in AEP records at index {index}: "
                f"expected {previous_hash}, got {observed_prev}"
            )
        previous_hash = sha256_text(canonical_json(record))
    return previous_hash


def _load_package(package_or_path: Mapping[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(package_or_path, Mapping):
        return dict(package_or_path)
    path = Path(package_or_path)
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuditChainError(f"invalid AEP JSON at {path}: {exc}") from exc
    except OSError as exc:
        raise AuditChainError(f"cannot read AEP package {path}: {exc}") from exc
    _require(isinstance(package, dict), "AEP package must be a JSON object")
    return package


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditChainError(message)


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = [
    "AEP_SCHEMA",
    "AEP_SCHEMA_VERSION",
    "AEPSourceVerification",
    "AEPVerification",
    "build_aep_export",
    "verify_aep_export",
    "write_aep_export",
]

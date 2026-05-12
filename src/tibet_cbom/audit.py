from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import CBOMDocument, SoMEvent


def _ts_to_iso(value) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    if isinstance(value, str) and value:
        return value
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_notes(record: dict) -> list[str]:
    notes: list[str] = []
    for key in (
        "intake_class",
        "disposition_hint",
        "surface_status",
        "disposition",
        "canonical_name",
    ):
        value = record.get(key)
        if value not in (None, "", [], {}):
            notes.append(f"{key}={value}")
    if record.get("renamed_by_operator"):
        notes.append("renamed_by_operator=true")
    return notes


def _load_audit_records(path: Path) -> list[dict]:
    records: list[dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def merge_audit_file(doc: CBOMDocument, audit_path: str) -> CBOMDocument:
    path = Path(audit_path)
    if not path.exists():
        raise FileNotFoundError(f"no such audit file: {path}")

    all_records = _load_audit_records(path)
    matched: list[dict] = [record for record in all_records if record.get("name") == doc.file_name]
    match_mode = "name"

    if not matched and doc.current_parent_action_id:
        parent_matches = [
            record for record in all_records
            if record.get("action_id") == doc.current_parent_action_id
        ]
        if parent_matches:
            matched = parent_matches
            match_mode = "parent_action_id"

    if not matched:
        doc.events.append(
            SoMEvent(
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                action="audit-unmatched",
                actor="tibet-cbom",
                action_id="act_audit_unmatched",
                notes=[
                    f"audit_file={path.name}",
                    "no records matched file name",
                    *(
                        [f"parent_action_id={doc.current_parent_action_id}"]
                        if doc.current_parent_action_id else []
                    ),
                ],
            )
        )
        return doc

    if len(matched) > 1:
        doc.events.append(
            SoMEvent(
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                action="audit-name-collision",
                actor="tibet-cbom",
                action_id="act_audit_collision",
                notes=[
                    f"audit_file={path.name}",
                    f"matched_records={len(matched)}",
                    f"match_mode={match_mode}",
                    "top-level fields not overwritten because audit match is ambiguous",
                ],
            )
        )

    for idx, record in enumerate(matched, start=1):
        stage = record.get("stage", "audit")
        actor = record.get("actor_id") or record.get("actor") or "continuityd"
        action_id = record.get("action_id") or f"act_audit_{idx}"
        doc.events.append(
            SoMEvent(
                timestamp=_ts_to_iso(record.get("ts")),
                action=stage,
                actor=actor,
                action_id=action_id,
                notes=[f"audit_match_mode={match_mode}", *_event_notes(record)],
            )
        )

    if len(matched) > 1:
        return doc

    latest = matched[-1]
    if match_mode == "name" and latest.get("canonical_name"):
        doc.canonical_name = latest["canonical_name"]
    if latest.get("continuity_id"):
        doc.continuity_id = latest["continuity_id"]
    if latest.get("object_id"):
        doc.object_id = latest["object_id"]
    if match_mode == "name" and latest.get("surface_status"):
        doc.surface_status = latest["surface_status"]
    if match_mode == "name" and latest.get("disposition"):
        doc.disposition_hint = latest["disposition"]
    elif match_mode == "name" and latest.get("disposition_hint"):
        doc.disposition_hint = latest["disposition_hint"]
    if match_mode == "name" and latest.get("intake_class"):
        doc.intake_class = latest["intake_class"]
    if match_mode == "parent_action_id":
        doc.events.append(
            SoMEvent(
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                action="audit-parent-resolved",
                actor="tibet-cbom",
                action_id="act_audit_parent_resolved",
                notes=[
                    f"audit_file={path.name}",
                    f"parent_action_id={doc.current_parent_action_id}",
                    f"inherited_object_id={doc.object_id or '<unknown>'}",
                    f"inherited_continuity_id={doc.continuity_id or '<unknown>'}",
                ],
            )
        )

    return doc

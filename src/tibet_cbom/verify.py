from __future__ import annotations

import json
from pathlib import Path

from .audit import merge_audit_file
from .inspect import inspect_path
from .manifest import extract_transition_payload
from .models import CBOMDocument


def _fact_map(doc: CBOMDocument) -> dict[str, str]:
    return {fact.key: fact.value for fact in doc.material_facts}


def _load_matching_audit_records(doc: CBOMDocument, audit_path: str | None) -> list[dict]:
    if not audit_path:
        return []
    path = Path(audit_path)
    if not path.exists():
        raise FileNotFoundError(f"no such audit file: {path}")

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
            if record.get("name") == doc.file_name:
                records.append(record)
    return records


def _check(
    checks: list[dict],
    *,
    name: str,
    ok: bool | None,
    summary: str,
    detail: str,
) -> None:
    status = "pass" if ok is True else "fail" if ok is False else "warn"
    checks.append(
        {
            "name": name,
            "status": status,
            "summary": summary,
            "detail": detail,
        }
    )


def build_verify_report(file_path: str, audit_path: str | None = None) -> dict:
    doc = inspect_path(file_path)
    raw_audit_records = _load_matching_audit_records(doc, audit_path)
    if audit_path:
        doc = merge_audit_file(doc, audit_path)
    facts = _fact_map(doc)
    transition_payload = extract_transition_payload(Path(file_path))
    transition = (
        transition_payload.get("ownership_transition")
        if isinstance(transition_payload, dict)
        else None
    )
    checks: list[dict] = []

    _check(
        checks,
        name="content-truth",
        ok=doc.object_class in {"tbz-family", "surface-claims-sealed", "opaque-file"},
        summary="object classified by content sniff",
        detail=f"object_class={doc.object_class} intake_class={doc.intake_class}",
    )

    manifest_present = facts.get("manifest_present") == "true"
    manifest_valid = facts.get("manifest_verify_valid") == "true"
    if doc.intake_class in {"sealed-tbz", "sealed-tbz-no-ext"}:
        _check(
            checks,
            name="manifest-present",
            ok=manifest_present,
            summary="sealed object should expose a manifest",
            detail=f"manifest_present={str(manifest_present).lower()}",
        )
        _check(
            checks,
            name="manifest-verify",
            ok=manifest_valid if manifest_present else False,
            summary="sealed manifest verifies under current tooling",
            detail=f"manifest_verify_valid={str(manifest_valid).lower()}",
        )
    else:
        _check(
            checks,
            name="manifest-verify",
            ok=None,
            summary="manifest verification skipped",
            detail=f"intake_class={doc.intake_class}",
        )

    if doc.surface_status == "disguised":
        _check(
            checks,
            name="surface-tension",
            ok=None,
            summary="surface/content tension detected",
            detail="object should stay in triage-oriented handling until explicitly accepted",
        )
    else:
        _check(
            checks,
            name="surface-tension",
            ok=True,
            summary="no disguised surface/content mismatch detected",
            detail=f"surface_status={doc.surface_status}",
        )

    if isinstance(transition, dict):
        required = (
            "action_id",
            "object_id",
            "continuity_id",
            "actor_id",
            "authority_mode",
            "transition_type",
            "status",
            "effective_assignee",
            "reason",
            "created_at",
        )
        missing = [key for key in required if not transition.get(key)]
        _check(
            checks,
            name="transition-required-fields",
            ok=not missing,
            summary="ownership transition carries required governance fields",
            detail="missing=" + (", ".join(missing) if missing else "<none>"),
        )
        _check(
            checks,
            name="transition-current-view",
            ok=(
                doc.current_action_id == transition.get("action_id")
                and doc.current_actor_id == transition.get("actor_id")
                and doc.current_transition_type == transition.get("transition_type")
                and doc.current_status == transition.get("status")
            ),
            summary="current authority view matches embedded transition payload",
            detail=(
                f"action={doc.current_action_id}/{transition.get('action_id')} "
                f"actor={doc.current_actor_id}/{transition.get('actor_id')} "
                f"type={doc.current_transition_type}/{transition.get('transition_type')} "
                f"status={doc.current_status}/{transition.get('status')}"
            ),
        )

        parent_action_id = transition.get("parent_action_id")
        if parent_action_id:
            matched_parent = any(
                record.get("action_id") == parent_action_id for record in raw_audit_records
            )
            _check(
                checks,
                name="transition-parent-link",
                ok=matched_parent if raw_audit_records else None,
                summary="parent authority step can be resolved from supplied audit context",
                detail=(
                    f"parent_action_id={parent_action_id} "
                    f"audit_records={len(raw_audit_records)} matched={str(matched_parent).lower()}"
                ),
            )
        else:
            _check(
                checks,
                name="transition-parent-link",
                ok=None,
                summary="no parent authority step declared",
                detail="root or first seeded authority step",
            )

        # ----------------------------------------------------------------
        # transition-authority check (introduced in tibet-cbom v0.2.0)
        #
        # Replaces the v0.1.x rewrap.py substring gate ('.admin' in
        # actor_id) with chain-walk discipline per RS-2026-001 §6.5:
        # authority is established by explicit cross-reference between
        # TIBET tokens, not by string-pattern matching on actor_id.
        #
        # Three categories per transition_type:
        #   self-issued  (freeze, release) — actor consistent across
        #     parent_action_id link (same chain)
        #   delegated    (handoff, takeover, supersede) — parent in
        #     different chain (cross-reference); parent_actor != actor
        #   chain-anchored (reclaim) — prior ownership token exists in
        #     audit context for this actor
        #
        # Handoff is delegated, not self-issued. Per RS-2026-001 Richard
        # Barron observation (21 May 2026): handoff is structurally a
        # bilateral consent-bound transfer (TAT Rule 1). Sender's
        # Transfer-Out Anchor and receiver's Transfer-In Anchor
        # converge via parent_action_id cross-reference. Self-handoff
        # (sender == receiver) is structurally rejected.
        #
        # Optional Ed25519 signature verification against AINS pubkey is
        # planned for v0.3.0 when the transition payload carries
        # signature bytes alongside the existing fields.
        # ----------------------------------------------------------------
        _TRANSITION_AUTHORITY = {
            "freeze": "self-issued",
            "release": "self-issued",
            "handoff": "delegated",       # bilateral consent (TAT Rule 1)
            "takeover": "delegated",
            "supersede": "delegated",
            "reclaim": "chain-anchored",
        }
        tx_type = transition.get("transition_type")
        tx_actor = transition.get("actor_id")
        category = _TRANSITION_AUTHORITY.get(tx_type, "unknown")

        if category == "self-issued":
            if parent_action_id:
                parent_record = next(
                    (
                        r for r in raw_audit_records
                        if r.get("action_id") == parent_action_id
                    ),
                    None,
                )
                if parent_record:
                    parent_actor = (
                        parent_record.get("actor_id")
                        or parent_record.get("actor")
                    )
                    ok = (parent_actor == tx_actor)
                    _check(
                        checks,
                        name="transition-authority",
                        ok=ok,
                        summary=(
                            "self-issued transition: actor consistent across parent link"
                            if ok else
                            "self-issued transition: actor differs from parent — authority break"
                        ),
                        detail=(
                            f"category=self-issued actor={tx_actor} "
                            f"parent_actor={parent_actor}"
                        ),
                    )
                else:
                    _check(
                        checks,
                        name="transition-authority",
                        ok=None,
                        summary="self-issued: parent_action_id not in audit (cannot verify chain)",
                        detail=(
                            f"category=self-issued actor={tx_actor} "
                            f"parent_action_id={parent_action_id}"
                        ),
                    )
            else:
                _check(
                    checks,
                    name="transition-authority",
                    ok=None,
                    summary="self-issued root event, no parent to verify",
                    detail=f"category=self-issued actor={tx_actor}",
                )
        elif category == "delegated":
            if parent_action_id:
                parent_record = next(
                    (
                        r for r in raw_audit_records
                        if r.get("action_id") == parent_action_id
                    ),
                    None,
                )
                if parent_record:
                    parent_actor = (
                        parent_record.get("actor_id")
                        or parent_record.get("actor")
                    )
                    # delegated requires cross-chain reference:
                    # parent_actor must be different identity than tx_actor
                    ok = (
                        parent_actor is not None
                        and parent_actor != tx_actor
                    )
                    _check(
                        checks,
                        name="transition-authority",
                        ok=ok,
                        summary=(
                            "delegated transition: cross-chain reference to delegating authority"
                            if ok else
                            "delegated transition lacks cross-chain reference (parent_actor == actor)"
                        ),
                        detail=(
                            f"category=delegated actor={tx_actor} "
                            f"delegating_actor={parent_actor}"
                        ),
                    )
                else:
                    _check(
                        checks,
                        name="transition-authority",
                        ok=False,
                        summary="delegated transition: parent (delegating authority) cannot be resolved",
                        detail=(
                            f"category=delegated actor={tx_actor} "
                            f"parent_action_id={parent_action_id}"
                        ),
                    )
            else:
                _check(
                    checks,
                    name="transition-authority",
                    ok=False,
                    summary="delegated transition without parent_action_id (cross-chain ref missing)",
                    detail=f"category=delegated actor={tx_actor}",
                )
        elif category == "chain-anchored":
            # reclaim: walk audit backward, find prior token where this
            # actor was active owner
            prior_ownership = any(
                (r.get("actor_id") or r.get("actor")) == tx_actor
                for r in raw_audit_records
            )
            _check(
                checks,
                name="transition-authority",
                ok=prior_ownership,
                summary=(
                    "chain-anchored reclaim: prior ownership token found in audit"
                    if prior_ownership else
                    "chain-anchored reclaim has no prior ownership in audit context"
                ),
                detail=f"category=chain-anchored actor={tx_actor}",
            )
        else:
            _check(
                checks,
                name="transition-authority",
                ok=False,
                summary=f"unknown transition_type {tx_type!r}, cannot determine authority category",
                detail="category=unknown",
            )
    else:
        _check(
            checks,
            name="transition-required-fields",
            ok=None,
            summary="no ownership transition embedded",
            detail="verify focused on object and manifest state only",
        )

    if raw_audit_records:
        unique_names = {record.get("name") for record in raw_audit_records}
        _check(
            checks,
            name="audit-context",
            ok=len(unique_names) == 1,
            summary="audit context resolved for this filename",
            detail=f"matched_records={len(raw_audit_records)} unique_names={len(unique_names)}",
        )
    elif audit_path:
        _check(
            checks,
            name="audit-context",
            ok=None,
            summary="no matching audit context found",
            detail=f"audit_file={Path(audit_path).name}",
        )

    failed = sum(1 for check in checks if check["status"] == "fail")
    warned = sum(1 for check in checks if check["status"] == "warn")
    verdict = "fail" if failed else "warn" if warned else "pass"

    return {
        "file": doc.file_name,
        "path": doc.file_path,
        "canonical_name": doc.canonical_name,
        "object_id": doc.object_id,
        "continuity_id": doc.continuity_id,
        "verdict": verdict,
        "summary": {
            "passed": sum(1 for check in checks if check["status"] == "pass"),
            "warned": warned,
            "failed": failed,
            "checks": len(checks),
        },
        "checks": checks,
    }


def render_verify_human(report: dict) -> str:
    lines = [
        f"File:        {report['file']}",
        f"Path:        {report['path']}",
        f"Verdict:     {report['verdict']}",
    ]
    if report.get("canonical_name"):
        lines.append(f"Canonical:   {report['canonical_name']}")
    if report.get("object_id"):
        lines.append(f"Object ID:   {report['object_id']}")
    if report.get("continuity_id"):
        lines.append(f"Continuity:  {report['continuity_id']}")
    lines.append("")
    lines.append("Checks:")
    for check in report["checks"]:
        lines.append(f"  - [{check['status']}] {check['name']}: {check['summary']}")
        lines.append(f"    {check['detail']}")
    return "\n".join(lines)

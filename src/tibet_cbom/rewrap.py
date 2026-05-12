from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time

from .inspect import inspect_path
from .models import CBOMDocument


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mint_action_id() -> str:
    return "act_" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")


def validate_transition_inputs(
    *,
    actor_id: str,
    authority_mode: str,
    transition_type: str,
    status: str,
    handoff_target: str | None = None,
    freeze_reason_code: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if transition_type == "handoff" and not handoff_target:
        errors.append("handoff requires --handoff-target")
    if transition_type == "freeze" and not freeze_reason_code:
        errors.append("freeze requires --freeze-reason-code")
    if authority_mode == "admin" and ".admin" not in actor_id:
        errors.append("authority-mode=admin expects an admin actor id")
    if transition_type == "freeze" and status != "frozen":
        errors.append("freeze transition should produce status=frozen")
    if transition_type == "takeover" and status not in {"admin-held", "frozen"}:
        errors.append("takeover transition should produce status=admin-held or frozen")
    if transition_type == "handoff" and status not in {"active", "handoff-pending"}:
        errors.append("handoff transition should produce status=active or handoff-pending")
    return errors


def build_ownership_transition_event(
    file_path: str,
    *,
    actor_id: str,
    authority_mode: str,
    transition_type: str,
    status: str,
    effective_assignee: str,
    reason: str,
    parent_action_id: str | None = None,
    continuity_id: str | None = None,
    object_id: str | None = None,
    handoff_target: str | None = None,
    previous_assignee: str | None = None,
    freeze_reason_code: str | None = None,
    resume_conditions: list[str] | None = None,
    authority_shift: str | None = None,
    policy_lane: str | None = None,
    surface_note: str | None = None,
    supersedes_action_id: str | None = None,
    trust_verdict_id: str | None = None,
    source_doc: CBOMDocument | None = None,
) -> dict:
    doc = source_doc or inspect_path(file_path)
    inherited_parent = doc.current_action_id
    if not inherited_parent:
        for event in reversed(doc.events):
            if event.action_id and not event.action_id.startswith("act_local_"):
                inherited_parent = event.action_id
                break

    event = {
        "event_type": "ownership-transition.v1",
        "action_id": _mint_action_id(),
        "object_id": object_id or doc.object_id or "obj_unknown",
        "continuity_id": continuity_id or doc.continuity_id or "cont_unknown",
        "actor_id": actor_id,
        "authority_mode": authority_mode,
        "transition_type": transition_type,
        "status": status,
        "effective_assignee": effective_assignee,
        "reason": reason,
        "created_at": _utc_now(),
    }

    chosen_parent = parent_action_id or inherited_parent
    if chosen_parent:
        event["parent_action_id"] = chosen_parent
    if handoff_target:
        event["handoff_target"] = handoff_target
    if previous_assignee:
        event["previous_assignee"] = previous_assignee
    if freeze_reason_code:
        event["freeze_reason_code"] = freeze_reason_code
    if resume_conditions:
        event["resume_conditions"] = resume_conditions
    if authority_shift:
        event["authority_shift"] = authority_shift
    if policy_lane:
        event["policy_lane"] = policy_lane
    if surface_note:
        event["surface_note"] = surface_note
    if supersedes_action_id:
        event["supersedes_action_id"] = supersedes_action_id
    if trust_verdict_id:
        event["trust_verdict_id"] = trust_verdict_id

    return {
        "source_file": str(Path(file_path).resolve()),
        "current_view": doc.to_dict(),
        "ownership_transition": event,
        "notes": [
            "sandbox sketch only",
            "does not repack or sign a new bundle yet",
            "meant to define the rewrap payload/event shape first",
            f"inherited_parent_action_id={inherited_parent or '<none>'}",
        ],
    }


def render_transition_preview(payload: dict) -> str:
    event = payload["ownership_transition"]
    lines = [
        f"Source:      {payload['source_file']}",
        f"Action:      {event['transition_type']}",
        f"Actor:       {event['actor_id']}",
        f"Authority:   {event['authority_mode']}",
        f"Status:      {event['status']}",
        f"Assignee:    {event['effective_assignee']}",
        f"Object ID:   {event['object_id']}",
        f"Continuity:  {event['continuity_id']}",
        f"Created At:  {event['created_at']}",
        f"Reason:      {event['reason']}",
    ]
    if event.get("parent_action_id"):
        lines.append(f"Parent:      {event['parent_action_id']}")
    if event.get("handoff_target"):
        lines.append(f"Handoff To:  {event['handoff_target']}")
    if event.get("freeze_reason_code"):
        lines.append(f"Freeze Code: {event['freeze_reason_code']}")
    return "\n".join(lines)


def render_transition_json(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _load_identity(identity_dir: Path):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import json as _json

    priv_bytes = (identity_dir / "identity.priv").read_bytes()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    info = _json.loads((identity_dir / "identity.json").read_text())

    from tibet_drop.crypto import IdentityKey  # type: ignore

    return IdentityKey(priv=priv, pub=priv.public_key()), info["aint"]


def emit_transition_bundle(
    payload: dict,
    *,
    bundle_out: str,
    identity_dir: str,
    receiver_aint: str = "self.aint",
    receiver_pubkey: str = "0" * 64,
    surface_time: str | None = None,
    surface_context: str = "ownership-transition",
    surface_profile: str = "admin",
    surface_priority: str = "normal",
) -> dict:
    import sys
    local_src = "/srv/jtel-stack/sandbox/airdrop-cli/src"
    if local_src not in sys.path:
        sys.path.insert(0, local_src)

    from tibet_drop.bundle import pack_bundle  # type: ignore
    import os

    out_path = Path(bundle_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    signer, sender_aint = _load_identity(Path(identity_dir))
    event = payload["ownership_transition"]
    if sender_aint != event["actor_id"]:
        raise ValueError(
            f"identity actor mismatch: identity_dir is {sender_aint}, "
            f"but transition actor is {event['actor_id']}"
        )
    content = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    block_name = "ownership-transition.json"
    if surface_time is None:
        surface_time = time.strftime("%Y-%m-%d", time.gmtime())

    manifest = pack_bundle(
        output_path=out_path,
        blocks=[(block_name, content)],
        sender_aint=sender_aint,
        sender_signer=signer,
        receiver_aint=receiver_aint,
        receiver_pubkey_hex=receiver_pubkey,
        payload_type="ai_state",
        tpid=os.urandom(16),
        surface_time_fragment=surface_time,
        surface_context=surface_context,
        surface_profile=surface_profile,
        surface_priority=surface_priority,
    )

    return {
        "bundle_out": str(out_path.resolve()),
        "sender_aint": sender_aint,
        "receiver_aint": receiver_aint,
        "manifest": manifest,
        "transition_action_id": event["action_id"],
    }


def render_authority_view(doc: CBOMDocument) -> str:
    lines = [
        f"File:        {doc.file_name}",
        f"Canonical:   {doc.canonical_name or '<unknown>'}",
        f"Object ID:   {doc.object_id or '<unknown>'}",
        f"Continuity:  {doc.continuity_id or '<unknown>'}",
        f"Actor:       {doc.current_actor_id or '<unknown>'}",
        f"Transition:  {doc.current_transition_type or '<none>'}",
        f"Status:      {doc.current_status or '<unknown>'}",
    ]
    return "\n".join(lines)

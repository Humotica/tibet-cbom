from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .manifest import (
    canonical_name_from_manifest,
    compare_surface_status,
    extract_transition_payload,
    inspect_manifest,
    verify_manifest,
)
from .models import CBOMDocument, MaterialFact, SoMEvent
from .sniff import IntakeClass, sniff_payload


def inspect_path(path_str: str) -> CBOMDocument:
    """Build a first-pass CBOM/SoM view from a local file path.

    This is intentionally conservative: it does not yet parse TBZ or
    continuity manifests. It only derives local facts and a plausible
    first event chain that later real parsers can replace or enrich.
    """
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"no such file: {path}")

    stat = path.stat()
    suffix = path.suffix.lower()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sniff = sniff_payload(path)
    manifest = None
    manifest_valid = False
    manifest_errors: list[str] = []
    transition_payload = None
    transition_event = None

    if sniff.intake_class in {IntakeClass.SEALED_TBZ, IntakeClass.SEALED_TBZ_NO_EXT}:
        manifest = inspect_manifest(path)
        manifest_valid, verified_manifest, manifest_errors = verify_manifest(path)
        if verified_manifest:
            manifest = verified_manifest
        transition_payload = extract_transition_payload(path)
        if isinstance(transition_payload, dict):
            candidate = transition_payload.get("ownership_transition")
            if isinstance(candidate, dict):
                transition_event = candidate

    if sniff.intake_class == IntakeClass.SEALED_TBZ:
        object_class = "tbz-family"
        canonical_name = canonical_name_from_manifest(manifest) or path.name
        human_name = None
        surface_status = (
            (compare_surface_status(path.name, manifest) or "MATCH").lower()
        )
    elif sniff.intake_class == IntakeClass.SEALED_TBZ_NO_EXT:
        object_class = "tbz-family"
        canonical_name = canonical_name_from_manifest(manifest)
        human_name = path.name
        surface_status = (
            (compare_surface_status(path.name, manifest) or
             "content-sealed-name-ambiguous").lower()
        )
    elif sniff.intake_class == IntakeClass.DISGUISED:
        object_class = "surface-claims-sealed"
        canonical_name = None
        human_name = path.name
        surface_status = "disguised"
    else:
        object_class = "opaque-file"
        canonical_name = None
        human_name = path.name
        surface_status = "unknown"

    facts = [
        MaterialFact("size_bytes", str(stat.st_size)),
        MaterialFact("suffix", suffix or "<none>"),
        MaterialFact("object_class", object_class),
        MaterialFact("intake_class", sniff.intake_class.value),
        MaterialFact("disposition_hint", sniff.disposition_hint),
        MaterialFact("magic_prefix_hex", sniff.magic_prefix_hex or "<none>"),
    ]
    if isinstance(manifest, dict):
        facts.append(MaterialFact("manifest_present", "true"))
        facts.append(MaterialFact("manifest_verify_valid", str(manifest_valid).lower()))
        if manifest.get("payload_type"):
            facts.append(MaterialFact("payload_type", str(manifest.get("payload_type"))))
        if manifest.get("sender_aint"):
            facts.append(MaterialFact("sender_aint", str(manifest.get("sender_aint"))))
        if manifest.get("receiver_aint"):
            facts.append(MaterialFact("receiver_aint", str(manifest.get("receiver_aint"))))
        if manifest.get("created_at"):
            facts.append(MaterialFact("manifest_created_at", str(manifest.get("created_at"))))
    else:
        facts.append(MaterialFact("manifest_present", "false"))
    if isinstance(transition_event, dict):
        facts.append(MaterialFact("ownership_transition_present", "true"))
        for key in ("actor_id", "transition_type", "status", "effective_assignee"):
            if transition_event.get(key):
                facts.append(MaterialFact(f"transition_{key}", str(transition_event.get(key))))
    else:
        facts.append(MaterialFact("ownership_transition_present", "false"))

    events = [
        SoMEvent(
            timestamp=now,
            action="observed",
            actor="tibet-cbom",
            action_id="act_local_observe",
            notes=[
                "local filesystem inspection",
                "magic-byte sniff applied",
                "manifest extracted" if manifest is not None else "no manifest extraction available",
            ],
        )
    ]
    if isinstance(manifest, dict):
        events.append(
            SoMEvent(
                timestamp=now,
                action="manifest-inspect",
                actor="tibet-cbom",
                action_id="act_manifest_inspect",
                notes=[
                    f"verify_valid={str(manifest_valid).lower()}",
                    f"canonical_name={canonical_name or '<none>'}",
                    f"surface_status={(surface_status or 'unknown').upper()}",
                    *[f"verify_error={err}" for err in manifest_errors[:3]],
                ],
            )
        )
    elif sniff.intake_class in {IntakeClass.SEALED_TBZ, IntakeClass.SEALED_TBZ_NO_EXT}:
        events.append(
            SoMEvent(
                timestamp=now,
                action="manifest-unavailable",
                actor="tibet-cbom",
                action_id="act_manifest_unavailable",
                notes=[
                    "bundle appears sealed by magic bytes",
                    *[f"verify_error={err}" for err in manifest_errors[:3]],
                ],
            )
        )
    if isinstance(transition_event, dict):
        events.append(
            SoMEvent(
                timestamp=str(transition_event.get("created_at") or now),
                action="ownership-transition",
                actor=str(transition_event.get("actor_id") or "unknown"),
                action_id=str(transition_event.get("action_id") or "act_transition_unknown"),
                notes=[
                    f"transition_type={transition_event.get('transition_type', '<none>')}",
                    f"status={transition_event.get('status', '<none>')}",
                    f"effective_assignee={transition_event.get('effective_assignee', '<none>')}",
                    *(
                        [f"handoff_target={transition_event.get('handoff_target')}"]
                        if transition_event.get("handoff_target") else []
                    ),
                ],
            )
        )

    if sniff.intake_class == IntakeClass.SEALED_TBZ_NO_EXT:
        events.append(
            SoMEvent(
                timestamp=now,
                action="sealed-no-ext",
                actor="tibet-cbom",
                action_id="act_tbz_no_ext",
                notes=[
                    "content identifies as TBZ family",
                    "surface name does not currently declare a recognized sealed extension",
                ],
            )
        )
    elif sniff.intake_class == IntakeClass.DISGUISED:
        events.append(
            SoMEvent(
                timestamp=now,
                action="surface-content-tension",
                actor="tibet-cbom",
                action_id="act_disguised",
                notes=[
                    "surface suggests sealed family",
                    "magic bytes do not confirm TBZ content",
                ],
            )
        )
    elif human_name and canonical_name is None and sniff.intake_class not in {
        IntakeClass.SEALED_TBZ_NO_EXT,
        IntakeClass.DISGUISED,
    }:
        events.append(
            SoMEvent(
                timestamp=now,
                action="human-name-only",
                actor="tibet-cbom",
                action_id="act_name_hint",
                notes=[
                    "file does not currently identify as TBZ family by suffix alone",
                    "later versions should inspect magic bytes and manifests",
                ],
            )
        )

    return CBOMDocument(
        file_path=str(path.resolve()),
        file_name=path.name,
        human_name=human_name,
        canonical_name=canonical_name,
        object_class=object_class,
        intake_class=sniff.intake_class.value,
        disposition_hint=sniff.disposition_hint,
        extension=sniff.extension,
        magic_prefix_hex=sniff.magic_prefix_hex,
        surface_extension_implies_sealed=sniff.surface_extension_implies_sealed,
        continuity_id=(
            str(transition_event.get("continuity_id")) if isinstance(transition_event, dict) and
            transition_event.get("continuity_id") is not None else
            str(manifest.get("continuity_id")) if isinstance(manifest, dict) and
            manifest.get("continuity_id") is not None else None
        ),
        object_id=(
            str(transition_event.get("object_id")) if isinstance(transition_event, dict) and
            transition_event.get("object_id") is not None else
            str(manifest.get("object_id")) if isinstance(manifest, dict) and
            manifest.get("object_id") is not None else None
        ),
        current_action_id=(
            str(transition_event.get("action_id")) if isinstance(transition_event, dict) and
            transition_event.get("action_id") is not None else None
        ),
        current_actor_id=(
            str(transition_event.get("actor_id")) if isinstance(transition_event, dict) and
            transition_event.get("actor_id") is not None else None
        ),
        current_transition_type=(
            str(transition_event.get("transition_type")) if isinstance(transition_event, dict) and
            transition_event.get("transition_type") is not None else None
        ),
        current_status=(
            str(transition_event.get("status")) if isinstance(transition_event, dict) and
            transition_event.get("status") is not None else None
        ),
        surface_status=surface_status,
        material_facts=facts,
        events=events,
    )

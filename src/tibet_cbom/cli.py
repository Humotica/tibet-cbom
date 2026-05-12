from __future__ import annotations

import argparse
import sys

from . import __version__
from .audit import merge_audit_file
from .inspect import inspect_path
from .render import render_human, render_json
from .rewrap import (
    build_ownership_transition_event,
    emit_transition_bundle,
    render_authority_view,
    render_transition_json,
    render_transition_preview,
    validate_transition_inputs,
)
from .verify import build_verify_report, render_verify_human


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tibet-cbom")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_inspect = sub.add_parser("inspect", help="Inspect one sealed object or local file")
    p_inspect.add_argument("file", help="Path to the file or envelope to inspect")
    p_inspect.add_argument("--audit-file", help="Optional continuityd audit JSONL to merge")
    p_inspect.add_argument("--json", action="store_true", help="Emit JSON")

    p_timeline = sub.add_parser("timeline", help="Reserved SoM-only event view")
    p_timeline.add_argument("file", help="Path to the file or envelope to inspect")
    p_timeline.add_argument("--audit-file", help="Optional continuityd audit JSONL to merge")
    p_timeline.add_argument("--json", action="store_true", help="Emit JSON")

    p_authority = sub.add_parser("authority", help="Show current authority / ownership-transition state")
    p_authority.add_argument("file", help="Path to the file or envelope to inspect")
    p_authority.add_argument("--audit-file", help="Optional continuityd audit JSONL to merge")
    p_authority.add_argument("--json", action="store_true", help="Emit JSON")

    p_verify = sub.add_parser("verify", help="Verify manifest and authority-step consistency")
    p_verify.add_argument("file", help="Path to the file or envelope to verify")
    p_verify.add_argument("--audit-file", help="Optional continuityd audit JSONL to resolve parent/action context")
    p_verify.add_argument("--json", action="store_true", help="Emit JSON")

    p_rewrap = sub.add_parser("rewrap", help="Sketch an ownership-transition rewrap event")
    p_rewrap.add_argument("file", help="Path to the file or envelope to rewrap")
    p_rewrap.add_argument("--audit-file", help="Optional continuityd audit JSONL to derive continuity inheritance")
    p_rewrap.add_argument("--actor", required=True, help="Authority actor issuing the transition")
    p_rewrap.add_argument("--authority-mode", required=True, choices=("agent", "admin", "triage", "shared", "system"))
    p_rewrap.add_argument("--transition-type", required=True, choices=("freeze", "takeover", "release", "handoff", "supersede", "reclaim"))
    p_rewrap.add_argument("--status", required=True, choices=("active", "frozen", "admin-held", "released", "handoff-pending", "closed"))
    p_rewrap.add_argument("--effective-assignee", required=True)
    p_rewrap.add_argument("--reason", required=True)
    p_rewrap.add_argument("--parent-action-id")
    p_rewrap.add_argument("--continuity-id")
    p_rewrap.add_argument("--object-id")
    p_rewrap.add_argument("--handoff-target")
    p_rewrap.add_argument("--previous-assignee")
    p_rewrap.add_argument("--freeze-reason-code")
    p_rewrap.add_argument("--resume-condition", action="append", dest="resume_conditions")
    p_rewrap.add_argument("--authority-shift")
    p_rewrap.add_argument("--policy-lane")
    p_rewrap.add_argument("--surface-note")
    p_rewrap.add_argument("--supersedes-action-id")
    p_rewrap.add_argument("--trust-verdict-id")
    p_rewrap.add_argument("--event-out", help="Optional path to write the transition payload JSON")
    p_rewrap.add_argument("--emit-bundle", help="Optional path to emit a sealed transition bundle")
    p_rewrap.add_argument("--identity-dir", help="Identity dir produced by tibet-drop init")
    p_rewrap.add_argument("--receiver-aint", default="self.aint")
    p_rewrap.add_argument("--receiver-pubkey", default="0" * 64)
    p_rewrap.add_argument("--surface-time")
    p_rewrap.add_argument("--surface-context", default="ownership-transition")
    p_rewrap.add_argument("--surface-profile", default="admin")
    p_rewrap.add_argument("--surface-priority", default="normal")
    p_rewrap.add_argument("--json", action="store_true", help="Emit JSON")

    return parser


def _cmd_inspect(args: argparse.Namespace) -> int:
    doc = inspect_path(args.file)
    if args.audit_file:
        doc = merge_audit_file(doc, args.audit_file)
    print(render_json(doc) if args.json else render_human(doc))
    return 0


def _cmd_timeline(args: argparse.Namespace) -> int:
    doc = inspect_path(args.file)
    if args.audit_file:
        doc = merge_audit_file(doc, args.audit_file)
    payload = {
        "file": doc.file_name,
        "events": [event.to_dict() for event in doc.events],
    }
    if args.json:
        import json

        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Timeline for {doc.file_name}")
        for event in doc.events:
            print(f"{event.timestamp}  {event.action:<16} {event.actor}  {event.action_id}")
            for note in event.notes:
                print(f"  - {note}")
    return 0


def _cmd_authority(args: argparse.Namespace) -> int:
    doc = inspect_path(args.file)
    if args.audit_file:
        doc = merge_audit_file(doc, args.audit_file)
    if args.json:
        payload = {
            "file": doc.file_name,
            "canonical_name": doc.canonical_name,
            "object_id": doc.object_id,
            "continuity_id": doc.continuity_id,
            "current_action_id": doc.current_action_id,
            "current_actor_id": doc.current_actor_id,
            "current_transition_type": doc.current_transition_type,
            "current_status": doc.current_status,
        }
        import json
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_authority_view(doc))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    report = build_verify_report(args.file, audit_path=args.audit_file)
    if args.json:
        import json

        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_verify_human(report))
    return 0 if report["verdict"] != "fail" else 1


def _cmd_rewrap(args: argparse.Namespace) -> int:
    errors = validate_transition_inputs(
        actor_id=args.actor,
        authority_mode=args.authority_mode,
        transition_type=args.transition_type,
        status=args.status,
        handoff_target=args.handoff_target,
        freeze_reason_code=args.freeze_reason_code,
    )
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    doc = inspect_path(args.file)
    if args.audit_file:
        doc = merge_audit_file(doc, args.audit_file)

    payload = build_ownership_transition_event(
        args.file,
        actor_id=args.actor,
        authority_mode=args.authority_mode,
        transition_type=args.transition_type,
        status=args.status,
        effective_assignee=args.effective_assignee,
        reason=args.reason,
        parent_action_id=args.parent_action_id,
        continuity_id=args.continuity_id,
        object_id=args.object_id,
        handoff_target=args.handoff_target,
        previous_assignee=args.previous_assignee,
        freeze_reason_code=args.freeze_reason_code,
        resume_conditions=args.resume_conditions,
        authority_shift=args.authority_shift,
        policy_lane=args.policy_lane,
        surface_note=args.surface_note,
        supersedes_action_id=args.supersedes_action_id,
        trust_verdict_id=args.trust_verdict_id,
        source_doc=doc,
    )
    if args.event_out:
        from pathlib import Path
        import json

        event_out = Path(args.event_out)
        event_out.parent.mkdir(parents=True, exist_ok=True)
        event_out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    bundle_result = None
    if args.emit_bundle:
        if not args.identity_dir:
            print("ERROR: --identity-dir is required with --emit-bundle", file=sys.stderr)
            return 1
        bundle_result = emit_transition_bundle(
            payload,
            bundle_out=args.emit_bundle,
            identity_dir=args.identity_dir,
            receiver_aint=args.receiver_aint,
            receiver_pubkey=args.receiver_pubkey,
            surface_time=args.surface_time,
            surface_context=args.surface_context,
            surface_profile=args.surface_profile,
            surface_priority=args.surface_priority,
        )
        payload["emitted_bundle"] = bundle_result

    print(render_transition_json(payload) if args.json else render_transition_preview(payload))
    if bundle_result and not args.json:
        print("")
        print(f"Bundle Out:  {bundle_result['bundle_out']}")
        print(f"Sender:      {bundle_result['sender_aint']}")
        print(f"Receiver:    {bundle_result['receiver_aint']}")
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == "inspect":
            raise SystemExit(_cmd_inspect(args))
        if args.command == "timeline":
            raise SystemExit(_cmd_timeline(args))
        if args.command == "authority":
            raise SystemExit(_cmd_authority(args))
        if args.command == "verify":
            raise SystemExit(_cmd_verify(args))
        if args.command == "rewrap":
            raise SystemExit(_cmd_rewrap(args))
        parser.error(f"unknown command: {args.command}")
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

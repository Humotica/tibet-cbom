from __future__ import annotations

import json

from .models import CBOMDocument


def render_json(doc: CBOMDocument) -> str:
    return json.dumps(doc.to_dict(), indent=2, sort_keys=True)


def render_human(doc: CBOMDocument) -> str:
    lines: list[str] = []
    lines.append(f"File:        {doc.file_name}")
    lines.append(f"Path:        {doc.file_path}")
    if doc.human_name:
        lines.append(f"Human Name:  {doc.human_name}")
    if doc.canonical_name:
        lines.append(f"Canonical:   {doc.canonical_name}")
    lines.append(f"Class:       {doc.object_class}")
    lines.append(f"Intake:      {doc.intake_class}")
    lines.append(f"Disposition: {doc.disposition_hint}")
    lines.append(f"Surface:     {doc.surface_status}")
    if doc.extension:
        lines.append(f"Extension:   {doc.extension}")
    if doc.magic_prefix_hex:
        lines.append(f"Magic:       {doc.magic_prefix_hex}")
    if doc.continuity_id:
        lines.append(f"Continuity:  {doc.continuity_id}")
    if doc.object_id:
        lines.append(f"Object ID:   {doc.object_id}")

    if doc.material_facts:
        lines.append("")
        lines.append("Materials:")
        for fact in doc.material_facts:
            lines.append(f"  - {fact.key}: {fact.value}")

    if doc.events:
        lines.append("")
        lines.append("Timeline:")
        for event in doc.events:
            lines.append(
                f"  {event.timestamp}  {event.action:<16} {event.actor}  {event.action_id}"
            )
            for note in event.notes:
                lines.append(f"    - {note}")

    return "\n".join(lines)

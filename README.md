# tibet-cbom

**Continuity Bill of Materials and State of Manifest inspector for sealed TIBET envelopes.**

This sandbox package sketches a tool family around two closely related
ideas:

- `CBOM`
  - continuity-aware bill of materials
  - what is in the object, plus how that object sits in a continuity
    chain
- `SoM`
  - State of Manifest
  - who asserted what, when, and how the manifest/surface relationship
    evolved over time

The first operator surface is intentionally simple:

```bash
tibet-cbom inspect file.tza
tibet-cbom inspect file.tza --json
```

And the more human/forensic framing remains available through the alias:

```bash
tibet-som inspect file.tza
```

## Semantic Surface Manifest (SSM)

A `.tza` output can carry **any** name or extension — `file-voor.claude`,
`log-2026.jasper.aint-lane5.log_storageQ2`. The name is a greeting and a useful
index; the **sealed manifest is the truth**.

`tibet_cbom.ssm` parses the surface into advisory hints (never authority) and
renders a posture card over an inspected object:

```python
from tibet_cbom import ssm

ssm.parse_surface_facets("log-2026.jasper.aint-lane5.log_storageQ2")
# -> {"quarter": "Q2", "year": "2026", "lane": "5", "actor": "jasper.aint",
#     "disposition": ["log", "storage"], "authority": "none — verify the manifest"}

print(ssm.ssm_card(doc).render())
# [SSM POSTURE: TZA#89421]
#  │││││_ Surface  : liquid (name + facets; a greeting)
#  ││││__ Seal     : byte-identical lock (Ed25519+PCLMULQDQ); magic = TBZ
#  │││___ Causal   : frozen at Lamport-tick #489201
#  ││____ Origin   : created by Route Posture #24358 (A5)
#  │_____ Manifest : .tza (tibet-zip) inviolable core
```

Two laws: **the surface carries no authority** — verified on magic bytes + signature,
never the filename, so zombie-zips (name says `.tza`, magic says otherwise) are refused —
and **the surface is still a useful index**: `tibet-audit` may bucket by `.log_storageQ2`,
but the manifest always wins on a drift.

## Why this exists

Normal file inspection answers:

- what is this file called
- how large is it
- what extension does it have

CBOM / SoM should answer richer questions:

- what class of sealed object is this
- what does its canonical surface appear to be
- what continuity identifiers are attached
- what events happened to it over time
- when was it renamed
- when was it verified
- when was a surface mismatch marked as partial or suspicious

That makes `tibet-cbom` feel less like `file(1)` and more like:

- `git log`
- for continuity-bearing envelopes

## Current sandbox scope

This skeleton does **not** claim full TBZ parsing yet.

It provides:

- package layout
- datamodel sketch
- CLI shape
- human and JSON rendering
- a first local file inspector that can grow into real manifest/event
  extraction later
- optional continuityd audit JSONL merge for early SoM timelines

## Commands

### `inspect`

Compact human summary or JSON object.

```bash
tibet-cbom inspect 2026-05-12.peer-eval.claude.urgent.tza
tibet-cbom inspect vergadering-dinsdag.pdf
tibet-cbom inspect file.tza --json
tibet-cbom inspect file.tza --audit-file expected-audit-example.jsonl
```

### `timeline`

Reserved for a later event-only view.

```bash
tibet-cbom timeline file.tza
tibet-cbom timeline file.tza --audit-file expected-audit-example.jsonl --json
```

### `authority`

Compact current authority state.

```bash
tibet-cbom authority file.tza
tibet-cbom authority file.tza --json
```

### `verify`

Explicit manifest and authority-step consistency check.

```bash
tibet-cbom verify file.tza
tibet-cbom verify file.tza --json
tibet-cbom verify file.tza --audit-file expected-audit-example.jsonl
```

### `rewrap`

Sandbox ownership-transition event sketch.

```bash
tibet-cbom rewrap task.tza \
  --audit-file audit.jsonl \
  --actor jis:humotica:jasper.admin \
  --authority-mode admin \
  --transition-type freeze \
  --status frozen \
  --effective-assignee jis:humotica:agent.ai \
  --reason "manual triage hold" \
  --freeze-reason-code human-review
```

If you also want a sandbox sealed bundle:

```bash
tibet-cbom rewrap task.tza \
  --audit-file audit.jsonl \
  --actor jis:humotica:jasper.admin \
  --authority-mode admin \
  --transition-type freeze \
  --status frozen \
  --effective-assignee jis:humotica:agent.ai \
  --reason "manual triage hold" \
  --freeze-reason-code human-review \
  --identity-dir ./admin-identity \
  --emit-bundle /tmp/admin-freeze.tza
```

Basic policy guards now apply:

- `handoff` requires `--handoff-target`
- `freeze` requires `--freeze-reason-code`
- `authority-mode=admin` expects an admin actor id
- emitted bundle signing identity must match transition actor

## Data model direction

The package uses two main record types:

- `CBOMDocument`
  - file path
  - human name
  - canonical name hint
  - continuity identifiers
  - surface status
  - material facts
  - event timeline
- `SoMEvent`
  - timestamp
  - action
  - actor
  - action id
  - notes / fields

This keeps the distinction clear:

- CBOM is the object summary
- SoM is the walkable event chain inside or around that object

Current known sealed payloads include:

- ownership transitions
- SAM gateway receipts

So a sealed `sam_gateway_receipt` is no longer treated as an opaque
payload; it lands as a first-class `sam-executed` event in the local
SoM timeline.

## Likely next steps

- extract canonical surface from real manifests
- map continuity IDs from real payloads/manifests
- render surface status transitions:
  - `MATCH`
  - `PARTIAL`
  - `DISGUISED`
  - `RENAMED`
- deepen `verify` into fuller chain integrity / succession validation

## Short framing

VCs answer:

- who are you

SoM answers:

- what did you manifest and when

CBOM then becomes the readable continuity-aware object view that ties
those together.


## Enterprise

For private hub hosting, SLA support, custom integrations, or compliance guidance:

| | |
|---|---|
| **Enterprise** | enterprise@humotica.com |
| **Support** | support@humotica.com |
| **Security** | security@humotica.com |

## License

MIT

## Credits

Designed by [Jasper van de Meent](https://github.com/jaspertvdm). Built by Jasper and [Root AI](https://humotica.com) as part of [HumoticaOS](https://humotica.com).

---

**Stack-positie:** Groep `evidence` · Bootstrap = OSAPI-handshake naar [`tibet`](https://pypi.org/project/tibet-core/) + [`jis`](https://pypi.org/project/jis-core/) (fail → snaft-rule + tibet-pol-rapport) · ← [`tibet-continuityd`](https://pypi.org/project/tibet-continuityd/) · [`tibet-sbom`](https://pypi.org/project/tibet-sbom/) → · See `STACK.md` · See `demo/golden-path/` for the spine end-to-end.

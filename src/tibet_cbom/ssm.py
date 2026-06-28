"""SSM — Semantic Surface Manifest.

Jasper's doctrine (28 June): once everything flows through tibet-zip (`.tza`), the
*name* of a file is a greeting, not the truth. `file-voor.claude`,
`log-2026.jasper.aint-lane5.log_storageQ2`, any name, any extension — the surface
is liquid; the sealed manifest is the inviolable core.

So we render a posture *over the artifact*, the sibling of route/repo/doc/machine
posture:

    [SSM POSTURE: TZA#89421]
     │││││
     │││││_ Surface  : liquid semantics (the name + human facets; a greeting)
     ││││__ Seal     : byte-identical cryptographic lock
     │││___ Causal   : frozen at a Lamport tick
     ││____ Origin   : created by a proven Route Posture
     │_____ Manifest : .tza (tibet-zip) inviolable core  <-- the truth

The two laws:

1. **The surface carries no authority.** A reader/auditor MAY read the surface for
   convenience (where to file it, what quarter, which lane) but MUST verify against
   the manifest. Truth is the sealed core, proven on magic-bytes + signature —
   never the filename. (`a bearer is never an authority`, applied to names.)
2. **The surface is a useful index anyway.** Human facets like `.log_storageQ2`
   are advisory hints both a human and tibet-audit may parse to organize, route,
   bucket, or stash a WIP — without ever granting trust.

This module reads the existing `CBOMDocument` (or a plain dict) and renders the
card, and parses surface facets into audit-readable hints. Pure stdlib.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ---- surface facet vocabulary (advisory hints, never authority) ---------------

_QUARTER = re.compile(r"q([1-4])(?![0-9])", re.IGNORECASE)
_YEAR = re.compile(r"\b(20\d{2})\b")
_LANE = re.compile(r"\blane[-_]?(\d+)\b", re.IGNORECASE)
_AINT = re.compile(r"\b([a-z0-9_]+\.aint)\b", re.IGNORECASE)
# disposition words a human/audit may stash in the surface
_DISPOSITION = {
    "log", "logs", "wip", "draft", "backup", "bak", "archive", "snapshot",
    "sent", "outbox", "inbox", "share", "shared", "received", "tmp", "scratch",
    "storage", "store", "cold", "hot",
}


def parse_surface_facets(name: str) -> dict[str, Any]:
    """Parse a surface name into advisory hints. NEVER authoritative.

    Example:
        "log-2026.jasper.aint-lane5.log_storageQ2"
        -> {"year": "2026", "actor": "jasper.aint", "lane": "5",
            "quarter": "Q2", "disposition": ["log", "storage"],
            "raw_tokens": [...], "authority": "none — verify the manifest"}
    """
    tokens = [t for t in re.split(r"[.\-_/\s]+", name) if t]
    facets: dict[str, Any] = {"raw_tokens": tokens}

    q = _QUARTER.search(name)
    if q:
        facets["quarter"] = "Q" + q.group(1)
    y = _YEAR.search(name)
    if y:
        facets["year"] = y.group(1)
    lane = _LANE.search(name)
    if lane:
        facets["lane"] = lane.group(1)
    aint = _AINT.search(name)
    if aint:
        facets["actor"] = aint.group(1).lower()

    disp = []
    for t in tokens:
        tl = t.lower()
        if tl in _DISPOSITION:
            disp.append(tl)
        else:  # glued token, e.g. "storageQ2" -> "storage"
            for w in _DISPOSITION:
                if len(w) >= 4 and tl.startswith(w):
                    disp.append(w)
                    break
    if disp:
        # de-dup, keep order
        facets["disposition"] = list(dict.fromkeys(disp))

    facets["authority"] = "none — these are hints; verify the sealed manifest"
    return facets


# ---- the SSM posture card ----------------------------------------------------

@dataclass
class SSMCard:
    tza_id: str
    surface: str
    seal: str
    causal: str
    origin: str
    manifest: str
    sealed: bool

    def render(self) -> str:
        return (
            f"[SSM POSTURE: TZA#{self.tza_id}]\n"
            f" │││││\n"
            f" │││││_ Surface  : {self.surface}\n"
            f" ││││__ Seal     : {self.seal}\n"
            f" │││___ Causal   : {self.causal}\n"
            f" ││____ Origin   : {self.origin}\n"
            f" │_____ Manifest : {self.manifest}"
        )


def _get(doc: Any, key: str, default=None):
    """Read a field from a CBOMDocument or a plain dict."""
    if isinstance(doc, dict):
        return doc.get(key, default)
    return getattr(doc, key, default)


def _facts(doc: Any) -> dict[str, str]:
    """Flatten material_facts (list of {key,value} or MaterialFact) to a dict."""
    out: dict[str, str] = {}
    for f in _get(doc, "material_facts", []) or []:
        k = f.get("key") if isinstance(f, dict) else getattr(f, "key", None)
        v = f.get("value") if isinstance(f, dict) else getattr(f, "value", None)
        if k is not None:
            out[k] = v
    return out


_TBZ_MAGIC_HEX = "54425a84"  # b"TBZ\x84"


def ssm_card(doc: Any) -> SSMCard:
    """Render the Semantic Surface Manifest posture card from a CBOM/.tza doc.

    Honest about what is proven: if the magic prefix is not the TBZ seal, the card
    says so (unsealed surface) rather than implying a lock that isn't there.
    """
    facts = _facts(doc)
    name = _get(doc, "human_name") or _get(doc, "file_name") or "(unnamed)"
    canonical = _get(doc, "canonical_name") or name
    magic = (_get(doc, "magic_prefix_hex", "") or "").lower().replace("0x", "")
    implies = bool(_get(doc, "surface_extension_implies_sealed", False))
    sealed = magic.startswith(_TBZ_MAGIC_HEX)

    tza_id = (_get(doc, "object_id") or _get(doc, "continuity_id")
              or facts.get("tza_id") or "????")

    facets = parse_surface_facets(name)
    hint_bits = []
    for k in ("year", "quarter", "lane", "actor"):
        if facets.get(k):
            hint_bits.append(f"{k}={facets[k]}")
    if facets.get("disposition"):
        hint_bits.append("disposition=" + "/".join(facets["disposition"]))
    surface = f"liquid: {name}"
    if hint_bits:
        surface += f"  [hints: {', '.join(hint_bits)} — advisory]"

    if sealed:
        seal_algo = facts.get("seal_algo", "Ed25519 sig + PCLMULQDQ digest")
        seal = f"byte-identical lock ({seal_algo}); magic {magic[:8]} = TBZ"
    elif implies:
        seal = "surface extension IMPLIES sealed, but magic bytes do NOT confirm — distrust"
    else:
        seal = "unsealed surface (no TBZ magic) — not a manifest, just a name"

    lamport = facts.get("lamport_tick") or _get(doc, "current_action_id")
    causal = f"frozen at Lamport-tick #{lamport}" if lamport else "no causal anchor (—)"

    rp = facts.get("route_posture")
    actor = _get(doc, "current_actor_id") or facets.get("actor")
    if rp:
        origin = f"created by Route Posture #{rp}"
        extra = [b for b in (facts.get("audit_mode"), facts.get("lane")) if b]
        if extra:
            origin += " (" + ", ".join(extra) + ")"
    elif actor:
        origin = f"actor {actor} (no proven route posture recorded)"
    else:
        origin = "origin unattested (—)"

    manifest = (".tza (tibet-zip) inviolable core" if sealed
                else f"NOT a sealed .tza — surface only: {canonical}")

    return SSMCard(tza_id=str(tza_id), surface=surface, seal=seal, causal=causal,
                   origin=origin, manifest=manifest, sealed=sealed)

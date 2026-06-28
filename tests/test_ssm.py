"""SSM — Semantic Surface Manifest. Surface = greeting; manifest = truth.

Covers Codex's contract test cases: sealed-all-facts, zombie surface, WIP,
surface drift (manifest wins), missing route posture (no inference from surface).
"""
from tibet_cbom import ssm

TBZ_MAGIC = "54425a84"  # b"TBZ\x84"


def _sealed_doc(**over):
    base = {
        "human_name": "log-2026.jasper.aint-lane5.log_storageQ2",
        "canonical_name": "tza-89421",
        "magic_prefix_hex": TBZ_MAGIC,
        "surface_extension_implies_sealed": True,
        "object_id": "89421",
        "current_actor_id": "jasper.aint",
        "material_facts": [
            {"key": "lamport_tick", "value": "489201"},
            {"key": "route_posture", "value": "24358"},
            {"key": "audit_mode", "value": "A5"},
            {"key": "seal_algo", "value": "Ed25519+PCLMULQDQ"},
        ],
    }
    base.update(over)
    return base


def test_facets_are_advisory_hints():
    f = ssm.parse_surface_facets("log-2026.jasper.aint-lane5.log_storageQ2")
    assert f["quarter"] == "Q2"
    assert f["year"] == "2026"
    assert f["lane"] == "5"
    assert f["actor"] == "jasper.aint"
    assert "log" in f["disposition"] and "storage" in f["disposition"]
    assert "none" in f["authority"].lower()  # never authority


def test_sealed_all_facts():
    card = ssm.ssm_card(_sealed_doc())
    assert card.sealed
    assert "489201" in card.causal
    assert "24358" in card.origin
    assert "A5" in card.origin
    assert "TBZ" in card.seal
    assert "inviolable core" in card.manifest


def test_zombie_surface_is_distrusted():
    # name says .tza, magic says PK (plain zip)
    doc = _sealed_doc(human_name="totally-legit.tza", magic_prefix_hex="504b0304")
    card = ssm.ssm_card(doc)
    assert not card.sealed
    assert "do NOT confirm" in card.seal or "distrust" in card.seal.lower()
    assert "NOT a sealed" in card.manifest


def test_wip_unsealed_indexes_but_claims_nothing():
    doc = {"human_name": "idee_voor.claude.draft.q3", "magic_prefix_hex": "", "material_facts": []}
    card = ssm.ssm_card(doc)
    assert not card.sealed
    assert "surface only" in card.manifest.lower() or "NOT a sealed" in card.manifest
    facets = ssm.parse_surface_facets("idee_voor.claude.draft.q3")
    assert facets["quarter"] == "Q3"
    assert "draft" in facets["disposition"]


def test_missing_route_posture_degrades_honestly():
    # no route_posture fact; must NOT infer one from the actor/lane surface
    doc = _sealed_doc(material_facts=[{"key": "lamport_tick", "value": "1"}])
    card = ssm.ssm_card(doc)
    assert "24358" not in card.origin                 # not invented
    assert "no proven route posture" in card.origin or "unattested" in card.origin


def test_surface_drift_manifest_wins():
    # surface facet says Q2, but the manifest causal anchor is the truth shown
    doc = _sealed_doc()  # surface has storageQ2, manifest lamport 489201
    card = ssm.ssm_card(doc)
    # the card's causal line comes from the manifest tick, never the surface quarter
    assert "489201" in card.causal
    assert "Q2" not in card.causal

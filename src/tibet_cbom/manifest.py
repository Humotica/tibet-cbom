from __future__ import annotations

import sys
import json
import tempfile
from pathlib import Path


def _load_tibet_drop_bundle():
    local_src = "/srv/jtel-stack/sandbox/airdrop-cli/src"
    if local_src not in sys.path:
        sys.path.insert(0, local_src)
    try:
        from tibet_drop import bundle as mod  # type: ignore
        return mod
    except ImportError:
        pass

    from tibet_drop import bundle as mod  # type: ignore
    return mod


def inspect_manifest(bundle_path: Path) -> dict | None:
    try:
        mod = _load_tibet_drop_bundle()
        manifest = mod.inspect_bundle(bundle_path)
        return manifest if isinstance(manifest, dict) else None
    except Exception:
        return None


def verify_manifest(bundle_path: Path) -> tuple[bool, dict | None, list[str]]:
    try:
        mod = _load_tibet_drop_bundle()
        valid, manifest, errors = mod.verify_bundle(bundle_path)
        return bool(valid), (manifest if isinstance(manifest, dict) else None), list(errors)
    except Exception as e:
        return False, None, [str(e)]


def manifest_surface(manifest: dict | None) -> dict | None:
    if not manifest:
        return None
    keys = (
        "surface_time_fragment",
        "surface_context",
        "surface_profile",
        "surface_priority",
    )
    if not any(manifest.get(k) is not None for k in keys):
        return None
    return {k: manifest.get(k) for k in keys}


def filename_surface(name: str) -> dict | None:
    try:
        mod = _load_tibet_drop_bundle()
        return mod.parse_surface_filename(name)
    except Exception:
        return None


def compare_surface_status(name: str, manifest: dict | None) -> str | None:
    try:
        mod = _load_tibet_drop_bundle()
        return mod.compare_surfaces(
            mod.parse_surface_filename(name),
            manifest_surface(manifest),
        )
    except Exception:
        return None


def canonical_name_from_manifest(manifest: dict | None) -> str | None:
    if not manifest:
        return None
    try:
        mod = _load_tibet_drop_bundle()
        return mod.canonical_filename(manifest)
    except Exception:
        return None


def extract_transition_payload(bundle_path: Path) -> dict | None:
    try:
        mod = _load_tibet_drop_bundle()
        with tempfile.TemporaryDirectory(prefix="tcbom-unpack-") as tmp:
            out = Path(tmp)
            mod.unpack_bundle(bundle_path, out)
            candidate = out / "ownership-transition.json"
            if not candidate.exists():
                return None
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
    except Exception:
        return None

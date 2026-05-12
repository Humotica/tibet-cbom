from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class MaterialFact:
    key: str
    value: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SoMEvent:
    timestamp: str
    action: str
    actor: str
    action_id: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CBOMDocument:
    file_path: str
    file_name: str
    human_name: str | None = None
    canonical_name: str | None = None
    object_class: str = "unknown"
    intake_class: str = "unknown"
    disposition_hint: str = "unknown"
    extension: str = ""
    magic_prefix_hex: str = ""
    surface_extension_implies_sealed: bool = False
    continuity_id: str | None = None
    object_id: str | None = None
    current_action_id: str | None = None
    current_parent_action_id: str | None = None
    current_actor_id: str | None = None
    current_transition_type: str | None = None
    current_status: str | None = None
    surface_status: str = "unknown"
    material_facts: list[MaterialFact] = field(default_factory=list)
    events: list[SoMEvent] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "human_name": self.human_name,
            "canonical_name": self.canonical_name,
            "object_class": self.object_class,
            "intake_class": self.intake_class,
            "disposition_hint": self.disposition_hint,
            "extension": self.extension,
            "magic_prefix_hex": self.magic_prefix_hex,
            "surface_extension_implies_sealed":
                self.surface_extension_implies_sealed,
            "continuity_id": self.continuity_id,
            "object_id": self.object_id,
            "current_action_id": self.current_action_id,
            "current_parent_action_id": self.current_parent_action_id,
            "current_actor_id": self.current_actor_id,
            "current_transition_type": self.current_transition_type,
            "current_status": self.current_status,
            "surface_status": self.surface_status,
            "material_facts": [fact.to_dict() for fact in self.material_facts],
            "events": [event.to_dict() for event in self.events],
        }

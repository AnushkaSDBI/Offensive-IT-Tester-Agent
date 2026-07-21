"""
Machine-readable governance policy: SSVC-inspired (Stakeholder-Specific Vulnerability
Categorization) prioritization for payload selection.

Rather than round-robin across surfaces (which treats every endpoint as equally
important), this lets an operator declare asset metadata — mission_prevalence (how
central this asset is to the organization's mission) and automatability (how easily
an attacker could automate exploitation) — and the planner prioritizes surfaces
accordingly. This is a governance input the planner must consume, not override; the
scope gate and enforcer remain the hard, un-overridable controls.

Inspired by CISA's SSVC framework and the aegissec-fedops governed-policy pattern,
independently implemented against our own AgentState/surface schema.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class MissionPrevalence(Enum):
    """How central this asset is to the organization's mission."""
    MINIMAL = 1
    SUPPORT = 2
    ESSENTIAL = 3


class Automatability(Enum):
    """How easily an attacker could automate exploitation of this surface."""
    NO = 1
    YES = 2


@dataclass
class AssetPolicy:
    """Governance metadata for one target path. Declared by the operator, not
    inferred by the agent — this is a human-authored input to planning."""
    path: str
    mission_prevalence: MissionPrevalence = MissionPrevalence.SUPPORT
    automatability: Automatability = Automatability.NO
    notes: str = ""

    @property
    def priority_score(self) -> int:
        """Simple SSVC-style combination: higher mission impact and higher
        automatability both raise priority. Range 2-6."""
        return self.mission_prevalence.value + self.automatability.value * 2


@dataclass
class SSVCPolicy:
    """A collection of per-path asset policies, plus a default for unlisted paths."""
    assets: Dict[str, AssetPolicy] = field(default_factory=dict)
    default_prevalence: MissionPrevalence = MissionPrevalence.SUPPORT
    default_automatability: Automatability = Automatability.NO

    def get(self, path: str) -> AssetPolicy:
        if path in self.assets:
            return self.assets[path]
        return AssetPolicy(path=path, mission_prevalence=self.default_prevalence,
                           automatability=self.default_automatability)

    def rank_surfaces(self, surfaces: List[dict]) -> List[dict]:
        """Sort surfaces by descending priority score. Ties broken by original
        order (stable sort) so behavior is deterministic and testable."""
        scored = [(self.get(s["path"]).priority_score, i, s) for i, s in enumerate(surfaces)]
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [s for _, _, s in scored]

    @classmethod
    def from_dict(cls, data: dict) -> "SSVCPolicy":
        """Build a policy from plain dicts, e.g. loaded from a YAML/JSON config file:

        {
          "assets": {
            "/login": {"mission_prevalence": "ESSENTIAL", "automatability": "YES"},
            "/profile": {"mission_prevalence": "MINIMAL"}
          },
          "default_prevalence": "SUPPORT",
          "default_automatability": "NO"
        }
        """
        assets = {}
        for path, meta in data.get("assets", {}).items():
            assets[path] = AssetPolicy(
                path=path,
                mission_prevalence=MissionPrevalence[meta.get("mission_prevalence", "SUPPORT")],
                automatability=Automatability[meta.get("automatability", "NO")],
                notes=meta.get("notes", ""),
            )
        return cls(
            assets=assets,
            default_prevalence=MissionPrevalence[data.get("default_prevalence", "SUPPORT")],
            default_automatability=Automatability[data.get("default_automatability", "NO")],
        )


def default_policy() -> SSVCPolicy:
    """A reasonable default: login/auth endpoints are essential + automatable
    (highest priority), transfer/financial endpoints are essential, everything
    else falls back to the SUPPORT/NO default."""
    return SSVCPolicy(assets={
        "/login": AssetPolicy("/login", MissionPrevalence.ESSENTIAL, Automatability.YES,
                              notes="Authentication is the highest-value target."),
        "/transfer": AssetPolicy("/transfer", MissionPrevalence.ESSENTIAL, Automatability.NO,
                                 notes="Financial action; high mission impact."),
        "/api/mcp/tools": AssetPolicy("/api/mcp/tools", MissionPrevalence.SUPPORT, Automatability.YES,
                                      notes="Downstream AI agents may auto-discover tools here."),
    })

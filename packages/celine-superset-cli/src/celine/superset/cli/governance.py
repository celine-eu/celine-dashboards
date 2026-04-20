"""Governance and ownership helpers for the CLI.

Minimal subset of celine-utils governance.py / owners.py models inlined here
to avoid pulling in celine-utils (and its heavy pipeline deps) as a CLI dep.
"""
from __future__ import annotations

import fnmatch
import glob as _glob
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Governance models
# ---------------------------------------------------------------------------

class GovernanceOwner(BaseModel):
    name: str
    type: str = "OWNER"


class GovernanceRule(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    access_level: Optional[str] = None
    ownership: List[GovernanceOwner] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    classification: Optional[str] = None
    source_system: Optional[str] = None


class GovernanceConfig(BaseModel):
    defaults: GovernanceRule = Field(default_factory=GovernanceRule)
    sources: Dict[str, GovernanceRule] = Field(default_factory=dict)


def _parse_rule(data: Dict[str, Any]) -> GovernanceRule:
    block = (data.get("governance") if "governance" in data else data) or {}
    owners = [
        GovernanceOwner(**o) if isinstance(o, dict) else GovernanceOwner(name=str(o))
        for o in (block.get("ownership") or [])
    ]
    return GovernanceRule(
        title=block.get("title"),
        description=block.get("description"),
        access_level=block.get("access_level"),
        ownership=owners,
        tags=block.get("tags") or [],
        classification=block.get("classification"),
        source_system=block.get("source_system"),
    )


def load_governance_file(path: Path) -> GovernanceConfig:
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    defaults = _parse_rule(raw.get("defaults") or {})
    sources = {
        pattern: _parse_rule(rule_data or {})
        for pattern, rule_data in (raw.get("sources") or {}).items()
    }
    return GovernanceConfig(defaults=defaults, sources=sources)


# ---------------------------------------------------------------------------
# Owners models
# ---------------------------------------------------------------------------

class OwnerEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    type: str = "schema:Organization"
    name: Optional[str] = None
    did: Optional[str] = None
    url: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)


class OwnersRegistry:
    def __init__(self, entries: list[OwnerEntry]) -> None:
        self._by_id: dict[str, OwnerEntry] = {e.id: e for e in entries}
        for e in entries:
            for alias in e.aliases:
                if alias not in self._by_id:
                    self._by_id[alias] = e

    def by_id(self, alias: str) -> Optional[OwnerEntry]:
        return self._by_id.get(alias)

    def all(self) -> list[OwnerEntry]:
        seen: set[str] = set()
        result = []
        for e in self._by_id.values():
            if e.id not in seen:
                seen.add(e.id)
                result.append(e)
        return result


def load_owners_yaml(path: Path) -> OwnersRegistry:
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    entries = [OwnerEntry.model_validate(item) for item in (raw.get("owners") or [])]
    return OwnersRegistry(entries)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def expand_globs(patterns: list[str]) -> list[Path]:
    """Expand shell-style glob patterns, return unique sorted paths."""
    found: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for match in _glob.glob(pattern, recursive=True):
            p = Path(match).resolve()
            if p not in seen:
                seen.add(p)
                found.append(p)
    return sorted(found)


def parse_source_key(key: str) -> Optional[tuple[str, str]]:
    """Extract (schema, table_name) from a governance source key.

    Examples:
      "datasets.ds_dev_gold.dwd_icon_d2_gusts" → ("ds_dev_gold", "dwd_icon_d2_gusts")
      "singer.tap-dwd.table"                   → ("tap-dwd", "table")
      "foo"                                    → None
    """
    parts = key.split(".")
    if len(parts) < 2:
        return None
    return parts[-2], parts[-1]


def collect_sources(
    configs: list[GovernanceConfig],
    filter_pattern: Optional[str],
) -> Dict[str, GovernanceRule]:
    """Merge sources from all configs and apply optional fnmatch filter.

    The filter is matched against source keys with an implicit leading wildcard
    so that ``ds_dev_gold.*`` matches ``datasets.ds_dev_gold.table``.
    """
    merged: Dict[str, GovernanceRule] = {}
    for cfg in configs:
        for key, rule in cfg.sources.items():
            merged[key] = rule

    if not filter_pattern:
        return merged

    pat = filter_pattern if filter_pattern.startswith("*") else f"*{filter_pattern}"
    return {k: v for k, v in merged.items() if fnmatch.fnmatch(k, pat)}

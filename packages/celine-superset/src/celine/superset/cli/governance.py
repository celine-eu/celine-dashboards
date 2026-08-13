"""Governance and ownership helpers for the CLI.

The models, the parser and the owner registry used to be inlined here — "to
avoid pulling in celine-utils (and its heavy pipeline deps) as a CLI dep", which
was a good reason: parsing a YAML file required dbt, Meltano, Prefect and
Keycloak.

`celine.governance` is that grammar with a core of pydantic + pyyaml +
jsonschema, so the copy stopped buying anything. What remains here is what is
genuinely Superset's: glob expansion, source-key parsing, and the source
collection policy.

This adoption was attempted once and reverted. `celine-utils` declared
`requires-python >= 3.12` while this package ships inside
`apache/superset:6.0.0`, which is Python 3.10, so the workspace could not lock.
That floor turned out to be inherited from an extras-only dependency that did
not need it either; `celine-utils` 2.1.0 declares `>=3.10` and the block is gone.
Nothing in this file changed in between.

Two behaviours the inlined copy had, now inherited rather than reimplemented:

- **Owner aliases resolve.** The copy registered them, so this CLI was already
  correct; `dataset-api` was the one that was not. Unchanged here.
- **Every governance field parses.** The copy read seven and dropped the rest,
  so `dcat`, `ontology` and `dataspace` blocks were silently invisible. Nothing
  in this CLI reads them yet, so this widens what is available without changing
  what is done.

`collect_sources` still does **not** merge `defaults` into each source — see its
docstring. That is a known defect, deliberately left alone: fixing it changes
live `datasource_access` tags and belongs in its own change.
"""
from __future__ import annotations

import fnmatch
import glob as _glob
from pathlib import Path
from typing import Dict, Optional

from celine.governance import (
    GovernanceConfig,
    GovernanceOwner,
    GovernanceResolver,
    GovernanceRule,
    OwnerEntry,
    OwnerOrganization,
    OwnersRegistry,
    load_owners_yaml,
)

__all__ = [
    "GovernanceConfig",
    "GovernanceOwner",
    "GovernanceRule",
    "OwnerEntry",
    "OwnerOrganization",
    "OwnersRegistry",
    "load_governance_file",
    "load_owners_yaml",
    "expand_globs",
    "parse_source_key",
    "collect_sources",
]


def load_governance_file(path: Path) -> GovernanceConfig:
    """Load one governance.yaml. No deployer overlay — this CLI takes explicit paths."""
    return GovernanceResolver.from_file(path).config


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

    Note that each rule is returned **as declared**, without its file's
    ``defaults`` merged in — so a dataset that inherits its `ownership` or
    `access_level` appears to have none, and this CLI falls back to
    ``"internal"``. That is a real defect, not an intentional policy, and it is
    left in place only because fixing it changes which Superset roles exist.
    ``GovernanceResolver.resolve`` is what does it correctly.
    """
    merged: Dict[str, GovernanceRule] = {}
    for cfg in configs:
        for key, rule in cfg.sources.items():
            merged[key] = rule

    if not filter_pattern:
        return merged

    pat = filter_pattern if filter_pattern.startswith("*") else f"*{filter_pattern}"
    return {k: v for k, v in merged.items() if fnmatch.fnmatch(k, pat)}

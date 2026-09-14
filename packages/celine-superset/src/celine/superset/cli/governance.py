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

Rules are resolved through `GovernanceResolver`, so each source inherits its
file's `defaults`, and deployer overlays are merged with `merge_configs`. Reading
rules as declared used to leave every dataset that inherits its owner untagged —
and untagged was open.

The access decision is here too, because it is a reading of governance: which
`celine_access` tag (see `celine.superset.plugin.access`) a dataset gets. It fails
closed — anything Superset cannot enforce, or cannot attribute to an org, is
operators only.
"""
from __future__ import annotations

import fnmatch
import glob as _glob
from dataclasses import dataclass
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
    merge_configs,
)

from celine.superset.plugin.access import (
    ACCESS_KEY,
    ACCESS_OPEN,
    ACCESS_OPERATORS,
    ACCESS_ORG,
    ORG_SLUGS_KEY,
)

__all__ = [
    "GovernanceConfig",
    "GovernanceOwner",
    "GovernanceRule",
    "OwnerEntry",
    "OwnerOrganization",
    "OwnersRegistry",
    "GovernanceFile",
    "AccessDecision",
    "load_governance_file",
    "load_owners_yaml",
    "expand_globs",
    "parse_source_key",
    "collect_sources",
    "decide_rule",
    "decide_dataset",
    "matching_rules",
]


@dataclass(frozen=True)
class GovernanceFile:
    """One governance.yaml with its deployer overlays merged in."""

    path: Path
    config: GovernanceConfig
    overlays: tuple[Path, ...] = ()


def load_governance_file(path: Path, overlay_dirs: tuple[Path, ...] = ()) -> GovernanceFile:
    """Load one governance.yaml and merge its deployer overlays.

    An overlay is ``governance.<app>.yaml``, where ``<app>`` is the directory
    holding the base file. It is looked up beside the file — as dataset-api does,
    through ``GovernanceResolver.from_file_with_override`` — and then in each
    ``overlay_dirs`` entry, in order, because a deployment keeps its overlays in a
    directory of their own.
    """
    app = path.parent.name
    overlays: list[Path] = []

    sibling = path.parent / f"governance.{app}.yaml"
    config = GovernanceResolver.from_file_with_override(path, app).config
    if sibling.is_file():
        overlays.append(sibling)

    for overlay_dir in overlay_dirs:
        candidate = overlay_dir / f"governance.{app}.yaml"
        if candidate.is_file() and candidate.resolve() != sibling.resolve():
            config = merge_configs(config, GovernanceResolver.from_file(candidate).config)
            overlays.append(candidate)

    return GovernanceFile(path=path, config=config, overlays=tuple(overlays))


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


def _key_filter(filter_pattern: Optional[str]):
    """fnmatch filter over source keys, with an implicit leading wildcard."""
    if not filter_pattern:
        return lambda key: True
    pat = filter_pattern if filter_pattern.startswith("*") else f"*{filter_pattern}"
    return lambda key: fnmatch.fnmatch(key, pat)


def collect_sources(
    configs: list[GovernanceConfig],
    filter_pattern: Optional[str],
) -> Dict[str, GovernanceRule]:
    """Resolve sources from all configs and apply optional fnmatch filter.

    The filter is matched against source keys with an implicit leading wildcard
    so that ``ds_dev_gold.*`` matches ``datasets.ds_dev_gold.table``.

    Each rule is resolved with its file's ``defaults`` merged in. Where files
    repeat a key the last one wins; this feeds owner and role creation only —
    the per-dataset decision (`matching_rules`, `decide_dataset`) sees every file.
    """
    keep = _key_filter(filter_pattern)
    merged: Dict[str, GovernanceRule] = {}
    for cfg in configs:
        resolver = GovernanceResolver(cfg)
        for key in cfg.sources:
            if keep(key):
                merged[key] = resolver.resolve(key)
    return merged


def matching_rules(
    files: list[GovernanceFile],
    schema: str,
    table: str,
    filter_pattern: Optional[str] = None,
) -> list[tuple[Path, str, GovernanceRule]]:
    """Every file's resolved rule for ``schema.table``, as ``(path, key, rule)``.

    Within one file an exact key wins over a glob, and the longest glob wins over
    a shorter one — ``GovernanceResolver``'s precedence. A key's schema and table
    segments are matched separately, so ``datasets.*_gold.foo`` matches.
    """
    keep = _key_filter(filter_pattern)
    found: list[tuple[Path, str, GovernanceRule]] = []
    for gf in files:
        exact: Optional[str] = None
        best_glob: Optional[str] = None
        for key in gf.config.sources:
            if not keep(key):
                continue
            parsed = parse_source_key(key)
            if parsed is None:
                continue
            key_schema, key_table = parsed
            if (key_schema, key_table) == (schema, table):
                exact = key
                break
            if fnmatch.fnmatchcase(schema, key_schema) and fnmatch.fnmatchcase(table, key_table):
                if best_glob is None or len(key) > len(best_glob):
                    best_glob = key
        key = exact or best_glob
        if key is not None:
            found.append((gf.path, key, GovernanceResolver(gf.config).resolve(key)))
    return found


@dataclass(frozen=True)
class AccessDecision:
    """The access tag one dataset gets, and why."""

    access: str
    org_slugs: tuple[str, ...] = ()
    reason: str = ""

    def as_extra(self) -> dict:
        return {ACCESS_KEY: self.access, ORG_SLUGS_KEY: list(self.org_slugs)}


_ORG_LEVELS = frozenset({"internal", "restricted"})


def decide_rule(rule: GovernanceRule, registry: OwnersRegistry) -> AccessDecision:
    """Fail-closed access decision for one resolved governance rule.

    In order:
      classification pii            → operators
      row_filters declared          → operators (Superset cannot apply them)
      dataspace.consent_required    → operators (Superset cannot check consent)
      access_level secret           → operators
      access_level open             → open
      internal | restricted | unset → org, for owners with a Keycloak organization;
                                      operators when there is none
      any other access_level        → operators
    """
    classification = (rule.classification or "").lower()
    if classification == "pii":
        return AccessDecision(ACCESS_OPERATORS, reason="classification pii")
    if rule.row_filters:
        return AccessDecision(ACCESS_OPERATORS, reason="row_filters cannot be enforced")
    if rule.dataspace is not None and rule.dataspace.consent_required:
        return AccessDecision(ACCESS_OPERATORS, reason="consent_required cannot be enforced")

    level = (rule.access_level or "internal").lower()
    if level == "secret":
        return AccessDecision(ACCESS_OPERATORS, reason="access_level secret")
    if level == "open":
        return AccessDecision(ACCESS_OPEN, reason="access_level open")
    if level not in _ORG_LEVELS:
        return AccessDecision(ACCESS_OPERATORS, reason=f"unknown access_level {level!r}")

    slugs: list[str] = []
    for owner in rule.ownership:
        entry = registry.by_id(owner.name)
        if entry is not None and not entry.has_kc_org:
            continue
        slug = entry.id if entry is not None else owner.name
        if slug not in slugs:
            slugs.append(slug)
    if not slugs:
        return AccessDecision(ACCESS_OPERATORS, reason="no owner with a Keycloak organization")
    return AccessDecision(ACCESS_ORG, tuple(sorted(slugs)), reason=f"access_level {level}")


def decide_dataset(
    matches: list[tuple[Path, str, GovernanceRule]],
    registry: OwnersRegistry,
) -> AccessDecision:
    """Access decision for one dataset, from every governance entry that matches it.

    No entry is operators only. Entries that reach different decisions are
    operators only too: the choice between them is not this CLI's to make.
    """
    if not matches:
        return AccessDecision(ACCESS_OPERATORS, reason="no governance entry")

    decisions = {path: decide_rule(rule, registry) for path, _, rule in matches}
    distinct = {(d.access, d.org_slugs) for d in decisions.values()}
    if len(distinct) > 1:
        detail = "; ".join(
            f"{path}: {d.access}{list(d.org_slugs) if d.org_slugs else ''}"
            for path, d in decisions.items()
        )
        return AccessDecision(ACCESS_OPERATORS, reason=f"conflicting governance entries ({detail})")
    return next(iter(decisions.values()))

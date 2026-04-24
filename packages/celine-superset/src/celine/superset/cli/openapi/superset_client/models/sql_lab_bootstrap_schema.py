from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sql_lab_bootstrap_schema_databases import SQLLabBootstrapSchemaDatabases
    from ..models.sql_lab_bootstrap_schema_queries import SQLLabBootstrapSchemaQueries
    from ..models.tab_state import TabState


T = TypeVar("T", bound="SQLLabBootstrapSchema")


@_attrs_define
class SQLLabBootstrapSchema:
    """
    Attributes:
        active_tab (TabState | Unset):
        databases (SQLLabBootstrapSchemaDatabases | Unset):
        queries (SQLLabBootstrapSchemaQueries | Unset):
        tab_state_ids (list[str] | Unset):
    """

    active_tab: TabState | Unset = UNSET
    databases: SQLLabBootstrapSchemaDatabases | Unset = UNSET
    queries: SQLLabBootstrapSchemaQueries | Unset = UNSET
    tab_state_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        active_tab: dict[str, Any] | Unset = UNSET
        if not isinstance(self.active_tab, Unset):
            active_tab = self.active_tab.to_dict()

        databases: dict[str, Any] | Unset = UNSET
        if not isinstance(self.databases, Unset):
            databases = self.databases.to_dict()

        queries: dict[str, Any] | Unset = UNSET
        if not isinstance(self.queries, Unset):
            queries = self.queries.to_dict()

        tab_state_ids: list[str] | Unset = UNSET
        if not isinstance(self.tab_state_ids, Unset):
            tab_state_ids = self.tab_state_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if active_tab is not UNSET:
            field_dict["active_tab"] = active_tab
        if databases is not UNSET:
            field_dict["databases"] = databases
        if queries is not UNSET:
            field_dict["queries"] = queries
        if tab_state_ids is not UNSET:
            field_dict["tab_state_ids"] = tab_state_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sql_lab_bootstrap_schema_databases import SQLLabBootstrapSchemaDatabases
        from ..models.sql_lab_bootstrap_schema_queries import SQLLabBootstrapSchemaQueries
        from ..models.tab_state import TabState

        d = dict(src_dict)
        _active_tab = d.pop("active_tab", UNSET)
        active_tab: TabState | Unset
        if isinstance(_active_tab, Unset):
            active_tab = UNSET
        else:
            active_tab = TabState.from_dict(_active_tab)

        _databases = d.pop("databases", UNSET)
        databases: SQLLabBootstrapSchemaDatabases | Unset
        if isinstance(_databases, Unset):
            databases = UNSET
        else:
            databases = SQLLabBootstrapSchemaDatabases.from_dict(_databases)

        _queries = d.pop("queries", UNSET)
        queries: SQLLabBootstrapSchemaQueries | Unset
        if isinstance(_queries, Unset):
            queries = UNSET
        else:
            queries = SQLLabBootstrapSchemaQueries.from_dict(_queries)

        tab_state_ids = cast(list[str], d.pop("tab_state_ids", UNSET))

        sql_lab_bootstrap_schema = cls(
            active_tab=active_tab,
            databases=databases,
            queries=queries,
            tab_state_ids=tab_state_ids,
        )

        sql_lab_bootstrap_schema.additional_properties = d
        return sql_lab_bootstrap_schema

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

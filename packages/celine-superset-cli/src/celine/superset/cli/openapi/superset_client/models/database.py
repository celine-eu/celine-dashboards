from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Database")


@_attrs_define
class Database:
    """
    Attributes:
        allow_multi_catalog (bool | Unset):
        allows_cost_estimate (bool | Unset):
        allows_subquery (bool | Unset):
        allows_virtual_table_explore (bool | Unset):
        backend (str | Unset):
        disable_data_preview (bool | Unset):
        disable_drill_to_detail (bool | Unset):
        explore_database_id (int | Unset):
        id (int | Unset):
        name (str | Unset):
    """

    allow_multi_catalog: bool | Unset = UNSET
    allows_cost_estimate: bool | Unset = UNSET
    allows_subquery: bool | Unset = UNSET
    allows_virtual_table_explore: bool | Unset = UNSET
    backend: str | Unset = UNSET
    disable_data_preview: bool | Unset = UNSET
    disable_drill_to_detail: bool | Unset = UNSET
    explore_database_id: int | Unset = UNSET
    id: int | Unset = UNSET
    name: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        allow_multi_catalog = self.allow_multi_catalog

        allows_cost_estimate = self.allows_cost_estimate

        allows_subquery = self.allows_subquery

        allows_virtual_table_explore = self.allows_virtual_table_explore

        backend = self.backend

        disable_data_preview = self.disable_data_preview

        disable_drill_to_detail = self.disable_drill_to_detail

        explore_database_id = self.explore_database_id

        id = self.id

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if allow_multi_catalog is not UNSET:
            field_dict["allow_multi_catalog"] = allow_multi_catalog
        if allows_cost_estimate is not UNSET:
            field_dict["allows_cost_estimate"] = allows_cost_estimate
        if allows_subquery is not UNSET:
            field_dict["allows_subquery"] = allows_subquery
        if allows_virtual_table_explore is not UNSET:
            field_dict["allows_virtual_table_explore"] = allows_virtual_table_explore
        if backend is not UNSET:
            field_dict["backend"] = backend
        if disable_data_preview is not UNSET:
            field_dict["disable_data_preview"] = disable_data_preview
        if disable_drill_to_detail is not UNSET:
            field_dict["disable_drill_to_detail"] = disable_drill_to_detail
        if explore_database_id is not UNSET:
            field_dict["explore_database_id"] = explore_database_id
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        allow_multi_catalog = d.pop("allow_multi_catalog", UNSET)

        allows_cost_estimate = d.pop("allows_cost_estimate", UNSET)

        allows_subquery = d.pop("allows_subquery", UNSET)

        allows_virtual_table_explore = d.pop("allows_virtual_table_explore", UNSET)

        backend = d.pop("backend", UNSET)

        disable_data_preview = d.pop("disable_data_preview", UNSET)

        disable_drill_to_detail = d.pop("disable_drill_to_detail", UNSET)

        explore_database_id = d.pop("explore_database_id", UNSET)

        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        database = cls(
            allow_multi_catalog=allow_multi_catalog,
            allows_cost_estimate=allows_cost_estimate,
            allows_subquery=allows_subquery,
            allows_virtual_table_explore=allows_virtual_table_explore,
            backend=backend,
            disable_data_preview=disable_data_preview,
            disable_drill_to_detail=disable_drill_to_detail,
            explore_database_id=explore_database_id,
            id=id,
            name=name,
        )

        database.additional_properties = d
        return database

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

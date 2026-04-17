from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Table")


@_attrs_define
class Table:
    """
    Attributes:
        database_id (int | Unset):
        description (str | Unset):
        expanded (bool | Unset):
        id (int | Unset):
        schema (str | Unset):
        tab_state_id (int | Unset):
        table (str | Unset):
    """

    database_id: int | Unset = UNSET
    description: str | Unset = UNSET
    expanded: bool | Unset = UNSET
    id: int | Unset = UNSET
    schema: str | Unset = UNSET
    tab_state_id: int | Unset = UNSET
    table: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database_id = self.database_id

        description = self.description

        expanded = self.expanded

        id = self.id

        schema = self.schema

        tab_state_id = self.tab_state_id

        table = self.table

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if database_id is not UNSET:
            field_dict["database_id"] = database_id
        if description is not UNSET:
            field_dict["description"] = description
        if expanded is not UNSET:
            field_dict["expanded"] = expanded
        if id is not UNSET:
            field_dict["id"] = id
        if schema is not UNSET:
            field_dict["schema"] = schema
        if tab_state_id is not UNSET:
            field_dict["tab_state_id"] = tab_state_id
        if table is not UNSET:
            field_dict["table"] = table

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        database_id = d.pop("database_id", UNSET)

        description = d.pop("description", UNSET)

        expanded = d.pop("expanded", UNSET)

        id = d.pop("id", UNSET)

        schema = d.pop("schema", UNSET)

        tab_state_id = d.pop("tab_state_id", UNSET)

        table = d.pop("table", UNSET)

        table = cls(
            database_id=database_id,
            description=description,
            expanded=expanded,
            id=id,
            schema=schema,
            tab_state_id=tab_state_id,
            table=table,
        )

        table.additional_properties = d
        return table

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

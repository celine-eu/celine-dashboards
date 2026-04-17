from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatabaseTablesQuerySchema")


@_attrs_define
class DatabaseTablesQuerySchema:
    """
    Attributes:
        schema_name (str):
        catalog_name (str | Unset):
        force (bool | Unset):
    """

    schema_name: str
    catalog_name: str | Unset = UNSET
    force: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        schema_name = self.schema_name

        catalog_name = self.catalog_name

        force = self.force

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "schema_name": schema_name,
            }
        )
        if catalog_name is not UNSET:
            field_dict["catalog_name"] = catalog_name
        if force is not UNSET:
            field_dict["force"] = force

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        schema_name = d.pop("schema_name")

        catalog_name = d.pop("catalog_name", UNSET)

        force = d.pop("force", UNSET)

        database_tables_query_schema = cls(
            schema_name=schema_name,
            catalog_name=catalog_name,
            force=force,
        )

        database_tables_query_schema.additional_properties = d
        return database_tables_query_schema

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

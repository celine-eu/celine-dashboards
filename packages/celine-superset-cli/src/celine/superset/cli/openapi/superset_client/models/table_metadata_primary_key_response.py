from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TableMetadataPrimaryKeyResponse")


@_attrs_define
class TableMetadataPrimaryKeyResponse:
    """
    Attributes:
        column_names (list[str] | Unset):
        name (str | Unset): The primary key index name
        type_ (str | Unset):
    """

    column_names: list[str] | Unset = UNSET
    name: str | Unset = UNSET
    type_: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        column_names: list[str] | Unset = UNSET
        if not isinstance(self.column_names, Unset):
            column_names = self.column_names

        name = self.name

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if column_names is not UNSET:
            field_dict["column_names"] = column_names
        if name is not UNSET:
            field_dict["name"] = name
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        column_names = cast(list[str], d.pop("column_names", UNSET))

        name = d.pop("name", UNSET)

        type_ = d.pop("type", UNSET)

        table_metadata_primary_key_response = cls(
            column_names=column_names,
            name=name,
            type_=type_,
        )

        table_metadata_primary_key_response.additional_properties = d
        return table_metadata_primary_key_response

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TableMetadataColumnsResponse")


@_attrs_define
class TableMetadataColumnsResponse:
    """
    Attributes:
        duplicates_constraint (str | Unset):
        keys (list[str] | Unset):
        long_type (str | Unset): The actual backend long type for the column
        name (str | Unset): The column name
        type_ (str | Unset): The column type
    """

    duplicates_constraint: str | Unset = UNSET
    keys: list[str] | Unset = UNSET
    long_type: str | Unset = UNSET
    name: str | Unset = UNSET
    type_: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        duplicates_constraint = self.duplicates_constraint

        keys: list[str] | Unset = UNSET
        if not isinstance(self.keys, Unset):
            keys = self.keys

        long_type = self.long_type

        name = self.name

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if duplicates_constraint is not UNSET:
            field_dict["duplicates_constraint"] = duplicates_constraint
        if keys is not UNSET:
            field_dict["keys"] = keys
        if long_type is not UNSET:
            field_dict["longType"] = long_type
        if name is not UNSET:
            field_dict["name"] = name
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        duplicates_constraint = d.pop("duplicates_constraint", UNSET)

        keys = cast(list[str], d.pop("keys", UNSET))

        long_type = d.pop("longType", UNSET)

        name = d.pop("name", UNSET)

        type_ = d.pop("type", UNSET)

        table_metadata_columns_response = cls(
            duplicates_constraint=duplicates_constraint,
            keys=keys,
            long_type=long_type,
            name=name,
            type_=type_,
        )

        table_metadata_columns_response.additional_properties = d
        return table_metadata_columns_response

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

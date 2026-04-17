from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.get_item_schema_keys_item import GetItemSchemaKeysItem, check_get_item_schema_keys_item
from ..types import UNSET, Unset

T = TypeVar("T", bound="GetItemSchema")


@_attrs_define
class GetItemSchema:
    """
    Attributes:
        columns (list[str] | Unset):
        keys (list[GetItemSchemaKeysItem] | Unset):
    """

    columns: list[str] | Unset = UNSET
    keys: list[GetItemSchemaKeysItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        columns: list[str] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = self.columns

        keys: list[str] | Unset = UNSET
        if not isinstance(self.keys, Unset):
            keys = []
            for keys_item_data in self.keys:
                keys_item: str = keys_item_data
                keys.append(keys_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if columns is not UNSET:
            field_dict["columns"] = columns
        if keys is not UNSET:
            field_dict["keys"] = keys

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        columns = cast(list[str], d.pop("columns", UNSET))

        _keys = d.pop("keys", UNSET)
        keys: list[GetItemSchemaKeysItem] | Unset = UNSET
        if _keys is not UNSET:
            keys = []
            for keys_item_data in _keys:
                keys_item = check_get_item_schema_keys_item(keys_item_data)

                keys.append(keys_item)

        get_item_schema = cls(
            columns=columns,
            keys=keys,
        )

        get_item_schema.additional_properties = d
        return get_item_schema

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

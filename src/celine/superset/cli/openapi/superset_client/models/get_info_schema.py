from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.get_info_schema_keys_item import GetInfoSchemaKeysItem, check_get_info_schema_keys_item
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_info_schema_add_columns import GetInfoSchemaAddColumns
    from ..models.get_info_schema_edit_columns import GetInfoSchemaEditColumns


T = TypeVar("T", bound="GetInfoSchema")


@_attrs_define
class GetInfoSchema:
    """
    Attributes:
        add_columns (GetInfoSchemaAddColumns | Unset):
        edit_columns (GetInfoSchemaEditColumns | Unset):
        keys (list[GetInfoSchemaKeysItem] | Unset):
    """

    add_columns: GetInfoSchemaAddColumns | Unset = UNSET
    edit_columns: GetInfoSchemaEditColumns | Unset = UNSET
    keys: list[GetInfoSchemaKeysItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        add_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.add_columns, Unset):
            add_columns = self.add_columns.to_dict()

        edit_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.edit_columns, Unset):
            edit_columns = self.edit_columns.to_dict()

        keys: list[str] | Unset = UNSET
        if not isinstance(self.keys, Unset):
            keys = []
            for keys_item_data in self.keys:
                keys_item: str = keys_item_data
                keys.append(keys_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if add_columns is not UNSET:
            field_dict["add_columns"] = add_columns
        if edit_columns is not UNSET:
            field_dict["edit_columns"] = edit_columns
        if keys is not UNSET:
            field_dict["keys"] = keys

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_info_schema_add_columns import GetInfoSchemaAddColumns
        from ..models.get_info_schema_edit_columns import GetInfoSchemaEditColumns

        d = dict(src_dict)
        _add_columns = d.pop("add_columns", UNSET)
        add_columns: GetInfoSchemaAddColumns | Unset
        if isinstance(_add_columns, Unset):
            add_columns = UNSET
        else:
            add_columns = GetInfoSchemaAddColumns.from_dict(_add_columns)

        _edit_columns = d.pop("edit_columns", UNSET)
        edit_columns: GetInfoSchemaEditColumns | Unset
        if isinstance(_edit_columns, Unset):
            edit_columns = UNSET
        else:
            edit_columns = GetInfoSchemaEditColumns.from_dict(_edit_columns)

        _keys = d.pop("keys", UNSET)
        keys: list[GetInfoSchemaKeysItem] | Unset = UNSET
        if _keys is not UNSET:
            keys = []
            for keys_item_data in _keys:
                keys_item = check_get_info_schema_keys_item(keys_item_data)

                keys.append(keys_item)

        get_info_schema = cls(
            add_columns=add_columns,
            edit_columns=edit_columns,
            keys=keys,
        )

        get_info_schema.additional_properties = d
        return get_info_schema

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

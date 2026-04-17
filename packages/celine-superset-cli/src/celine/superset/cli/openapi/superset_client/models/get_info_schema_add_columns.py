from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.get_info_schema_add_columns_additional_property import GetInfoSchemaAddColumnsAdditionalProperty


T = TypeVar("T", bound="GetInfoSchemaAddColumns")


@_attrs_define
class GetInfoSchemaAddColumns:
    """ """

    additional_properties: dict[str, GetInfoSchemaAddColumnsAdditionalProperty] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        for prop_name, prop in self.additional_properties.items():
            field_dict[prop_name] = prop.to_dict()

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_info_schema_add_columns_additional_property import GetInfoSchemaAddColumnsAdditionalProperty

        d = dict(src_dict)
        get_info_schema_add_columns = cls()

        additional_properties = {}
        for prop_name, prop_dict in d.items():
            additional_property = GetInfoSchemaAddColumnsAdditionalProperty.from_dict(prop_dict)

            additional_properties[prop_name] = additional_property

        get_info_schema_add_columns.additional_properties = additional_properties
        return get_info_schema_add_columns

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> GetInfoSchemaAddColumnsAdditionalProperty:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: GetInfoSchemaAddColumnsAdditionalProperty) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

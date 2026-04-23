from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GetApiV1SecurityRolesInfoResponse200FiltersColumnNameItem")


@_attrs_define
class GetApiV1SecurityRolesInfoResponse200FiltersColumnNameItem:
    """
    Attributes:
        name (str | Unset): The filter name. Will be translated by babel
        operator (str | Unset): The filter operation key to use on list filters
    """

    name: str | Unset = UNSET
    operator: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        operator = self.operator

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if operator is not UNSET:
            field_dict["operator"] = operator

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name", UNSET)

        operator = d.pop("operator", UNSET)

        get_api_v1_security_roles_info_response_200_filters_column_name_item = cls(
            name=name,
            operator=operator,
        )

        get_api_v1_security_roles_info_response_200_filters_column_name_item.additional_properties = d
        return get_api_v1_security_roles_info_response_200_filters_column_name_item

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

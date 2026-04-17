from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.get_api_v1_security_roles_search_q_filters_item_col import (
    GetApiV1SecurityRolesSearchQFiltersItemCol,
    check_get_api_v1_security_roles_search_q_filters_item_col,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="GetApiV1SecurityRolesSearchQFiltersItem")


@_attrs_define
class GetApiV1SecurityRolesSearchQFiltersItem:
    """
    Attributes:
        col (GetApiV1SecurityRolesSearchQFiltersItemCol | Unset):
        value (str | Unset):
    """

    col: GetApiV1SecurityRolesSearchQFiltersItemCol | Unset = UNSET
    value: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        col: str | Unset = UNSET
        if not isinstance(self.col, Unset):
            col = self.col

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if col is not UNSET:
            field_dict["col"] = col
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _col = d.pop("col", UNSET)
        col: GetApiV1SecurityRolesSearchQFiltersItemCol | Unset
        if isinstance(_col, Unset):
            col = UNSET
        else:
            col = check_get_api_v1_security_roles_search_q_filters_item_col(_col)

        value = d.pop("value", UNSET)

        get_api_v1_security_roles_search_q_filters_item = cls(
            col=col,
            value=value,
        )

        get_api_v1_security_roles_search_q_filters_item.additional_properties = d
        return get_api_v1_security_roles_search_q_filters_item

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

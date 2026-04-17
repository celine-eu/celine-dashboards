from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RolePermissionListSchema")


@_attrs_define
class RolePermissionListSchema:
    """
    Attributes:
        id (int | Unset):
        permission_name (str | Unset):
        view_menu_name (str | Unset):
    """

    id: int | Unset = UNSET
    permission_name: str | Unset = UNSET
    view_menu_name: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        permission_name = self.permission_name

        view_menu_name = self.view_menu_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if permission_name is not UNSET:
            field_dict["permission_name"] = permission_name
        if view_menu_name is not UNSET:
            field_dict["view_menu_name"] = view_menu_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        permission_name = d.pop("permission_name", UNSET)

        view_menu_name = d.pop("view_menu_name", UNSET)

        role_permission_list_schema = cls(
            id=id,
            permission_name=permission_name,
            view_menu_name=view_menu_name,
        )

        role_permission_list_schema.additional_properties = d
        return role_permission_list_schema

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

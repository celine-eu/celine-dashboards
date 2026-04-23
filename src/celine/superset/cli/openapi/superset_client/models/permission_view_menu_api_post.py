from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PermissionViewMenuApiPost")


@_attrs_define
class PermissionViewMenuApiPost:
    """
    Attributes:
        permission_id (Any | Unset):
        view_menu_id (Any | Unset):
    """

    permission_id: Any | Unset = UNSET
    view_menu_id: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        permission_id = self.permission_id

        view_menu_id = self.view_menu_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if permission_id is not UNSET:
            field_dict["permission_id"] = permission_id
        if view_menu_id is not UNSET:
            field_dict["view_menu_id"] = view_menu_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        permission_id = d.pop("permission_id", UNSET)

        view_menu_id = d.pop("view_menu_id", UNSET)

        permission_view_menu_api_post = cls(
            permission_id=permission_id,
            view_menu_id=view_menu_id,
        )

        permission_view_menu_api_post.additional_properties = d
        return permission_view_menu_api_post

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

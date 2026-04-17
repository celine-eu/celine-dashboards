from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RolePermissionPostSchema")


@_attrs_define
class RolePermissionPostSchema:
    """
    Attributes:
        permission_view_menu_ids (list[int]): List of permission view menu id
    """

    permission_view_menu_ids: list[int]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        permission_view_menu_ids = self.permission_view_menu_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "permission_view_menu_ids": permission_view_menu_ids,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        permission_view_menu_ids = cast(list[int], d.pop("permission_view_menu_ids"))

        role_permission_post_schema = cls(
            permission_view_menu_ids=permission_view_menu_ids,
        )

        role_permission_post_schema.additional_properties = d
        return role_permission_post_schema

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

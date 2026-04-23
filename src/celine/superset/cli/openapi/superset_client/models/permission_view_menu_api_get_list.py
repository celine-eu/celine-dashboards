from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.permission_view_menu_api_get_list_permission import PermissionViewMenuApiGetListPermission
    from ..models.permission_view_menu_api_get_list_view_menu import PermissionViewMenuApiGetListViewMenu


T = TypeVar("T", bound="PermissionViewMenuApiGetList")


@_attrs_define
class PermissionViewMenuApiGetList:
    """
    Attributes:
        id (int | Unset):
        permission (PermissionViewMenuApiGetListPermission | Unset):
        view_menu (PermissionViewMenuApiGetListViewMenu | Unset):
    """

    id: int | Unset = UNSET
    permission: PermissionViewMenuApiGetListPermission | Unset = UNSET
    view_menu: PermissionViewMenuApiGetListViewMenu | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        permission: dict[str, Any] | Unset = UNSET
        if not isinstance(self.permission, Unset):
            permission = self.permission.to_dict()

        view_menu: dict[str, Any] | Unset = UNSET
        if not isinstance(self.view_menu, Unset):
            view_menu = self.view_menu.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if permission is not UNSET:
            field_dict["permission"] = permission
        if view_menu is not UNSET:
            field_dict["view_menu"] = view_menu

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.permission_view_menu_api_get_list_permission import PermissionViewMenuApiGetListPermission
        from ..models.permission_view_menu_api_get_list_view_menu import PermissionViewMenuApiGetListViewMenu

        d = dict(src_dict)
        id = d.pop("id", UNSET)

        _permission = d.pop("permission", UNSET)
        permission: PermissionViewMenuApiGetListPermission | Unset
        if isinstance(_permission, Unset):
            permission = UNSET
        else:
            permission = PermissionViewMenuApiGetListPermission.from_dict(_permission)

        _view_menu = d.pop("view_menu", UNSET)
        view_menu: PermissionViewMenuApiGetListViewMenu | Unset
        if isinstance(_view_menu, Unset):
            view_menu = UNSET
        else:
            view_menu = PermissionViewMenuApiGetListViewMenu.from_dict(_view_menu)

        permission_view_menu_api_get_list = cls(
            id=id,
            permission=permission,
            view_menu=view_menu,
        )

        permission_view_menu_api_get_list.additional_properties = d
        return permission_view_menu_api_get_list

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

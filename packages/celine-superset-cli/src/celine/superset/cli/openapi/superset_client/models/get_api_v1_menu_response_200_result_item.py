from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_menu_response_200_result_item_childs_item import (
        GetApiV1MenuResponse200ResultItemChildsItem,
    )


T = TypeVar("T", bound="GetApiV1MenuResponse200ResultItem")


@_attrs_define
class GetApiV1MenuResponse200ResultItem:
    """
    Attributes:
        childs (list[GetApiV1MenuResponse200ResultItemChildsItem] | Unset):
        icon (str | Unset): Icon name to show for this menu item
        label (str | Unset): Pretty name for the menu item
        name (str | Unset): The internal menu item name, maps to permission_name
        url (str | Unset): The URL for the menu item
    """

    childs: list[GetApiV1MenuResponse200ResultItemChildsItem] | Unset = UNSET
    icon: str | Unset = UNSET
    label: str | Unset = UNSET
    name: str | Unset = UNSET
    url: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        childs: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.childs, Unset):
            childs = []
            for childs_item_data in self.childs:
                childs_item = childs_item_data.to_dict()
                childs.append(childs_item)

        icon = self.icon

        label = self.label

        name = self.name

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if childs is not UNSET:
            field_dict["childs"] = childs
        if icon is not UNSET:
            field_dict["icon"] = icon
        if label is not UNSET:
            field_dict["label"] = label
        if name is not UNSET:
            field_dict["name"] = name
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_menu_response_200_result_item_childs_item import (
            GetApiV1MenuResponse200ResultItemChildsItem,
        )

        d = dict(src_dict)
        _childs = d.pop("childs", UNSET)
        childs: list[GetApiV1MenuResponse200ResultItemChildsItem] | Unset = UNSET
        if _childs is not UNSET:
            childs = []
            for childs_item_data in _childs:
                childs_item = GetApiV1MenuResponse200ResultItemChildsItem.from_dict(childs_item_data)

                childs.append(childs_item)

        icon = d.pop("icon", UNSET)

        label = d.pop("label", UNSET)

        name = d.pop("name", UNSET)

        url = d.pop("url", UNSET)

        get_api_v1_menu_response_200_result_item = cls(
            childs=childs,
            icon=icon,
            label=label,
            name=name,
            url=url,
        )

        get_api_v1_menu_response_200_result_item.additional_properties = d
        return get_api_v1_menu_response_200_result_item

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

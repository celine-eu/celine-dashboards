from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Theme")


@_attrs_define
class Theme:
    """
    Attributes:
        id (int | Unset):
        json_data (str | Unset):
        theme_name (str | Unset):
    """

    id: int | Unset = UNSET
    json_data: str | Unset = UNSET
    theme_name: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        json_data = self.json_data

        theme_name = self.theme_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if json_data is not UNSET:
            field_dict["json_data"] = json_data
        if theme_name is not UNSET:
            field_dict["theme_name"] = theme_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        json_data = d.pop("json_data", UNSET)

        theme_name = d.pop("theme_name", UNSET)

        theme = cls(
            id=id,
            json_data=json_data,
            theme_name=theme_name,
        )

        theme.additional_properties = d
        return theme

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

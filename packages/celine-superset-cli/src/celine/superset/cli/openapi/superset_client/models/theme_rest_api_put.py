from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ThemeRestApiPut")


@_attrs_define
class ThemeRestApiPut:
    """
    Attributes:
        json_data (str):
        theme_name (str):
    """

    json_data: str
    theme_name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        json_data = self.json_data

        theme_name = self.theme_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "json_data": json_data,
                "theme_name": theme_name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        json_data = d.pop("json_data")

        theme_name = d.pop("theme_name")

        theme_rest_api_put = cls(
            json_data=json_data,
            theme_name=theme_name,
        )

        theme_rest_api_put.additional_properties = d
        return theme_rest_api_put

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

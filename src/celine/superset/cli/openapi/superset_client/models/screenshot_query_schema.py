from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScreenshotQuerySchema")


@_attrs_define
class ScreenshotQuerySchema:
    """
    Attributes:
        force (bool | Unset):
        thumb_size (list[int] | Unset):
        window_size (list[int] | Unset):
    """

    force: bool | Unset = UNSET
    thumb_size: list[int] | Unset = UNSET
    window_size: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        force = self.force

        thumb_size: list[int] | Unset = UNSET
        if not isinstance(self.thumb_size, Unset):
            thumb_size = self.thumb_size

        window_size: list[int] | Unset = UNSET
        if not isinstance(self.window_size, Unset):
            window_size = self.window_size

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if force is not UNSET:
            field_dict["force"] = force
        if thumb_size is not UNSET:
            field_dict["thumb_size"] = thumb_size
        if window_size is not UNSET:
            field_dict["window_size"] = window_size

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        force = d.pop("force", UNSET)

        thumb_size = cast(list[int], d.pop("thumb_size", UNSET))

        window_size = cast(list[int], d.pop("window_size", UNSET))

        screenshot_query_schema = cls(
            force=force,
            thumb_size=thumb_size,
            window_size=window_size,
        )

        screenshot_query_schema.additional_properties = d
        return screenshot_query_schema

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecentActivitySchema")


@_attrs_define
class RecentActivitySchema:
    """
    Attributes:
        action (str | Unset): Action taken describing type of activity
        item_title (str | Unset): Title of item
        item_type (str | Unset): Type of item, e.g. slice or dashboard
        item_url (str | Unset): URL to item
        time (float | Unset): Time of activity, in epoch milliseconds
        time_delta_humanized (str | Unset): Human-readable description of how long ago activity took place.
    """

    action: str | Unset = UNSET
    item_title: str | Unset = UNSET
    item_type: str | Unset = UNSET
    item_url: str | Unset = UNSET
    time: float | Unset = UNSET
    time_delta_humanized: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action = self.action

        item_title = self.item_title

        item_type = self.item_type

        item_url = self.item_url

        time = self.time

        time_delta_humanized = self.time_delta_humanized

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if action is not UNSET:
            field_dict["action"] = action
        if item_title is not UNSET:
            field_dict["item_title"] = item_title
        if item_type is not UNSET:
            field_dict["item_type"] = item_type
        if item_url is not UNSET:
            field_dict["item_url"] = item_url
        if time is not UNSET:
            field_dict["time"] = time
        if time_delta_humanized is not UNSET:
            field_dict["time_delta_humanized"] = time_delta_humanized

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action = d.pop("action", UNSET)

        item_title = d.pop("item_title", UNSET)

        item_type = d.pop("item_type", UNSET)

        item_url = d.pop("item_url", UNSET)

        time = d.pop("time", UNSET)

        time_delta_humanized = d.pop("time_delta_humanized", UNSET)

        recent_activity_schema = cls(
            action=action,
            item_title=item_title,
            item_type=item_type,
            item_url=item_url,
            time=time,
            time_delta_humanized=time_delta_humanized,
        )

        recent_activity_schema.additional_properties = d
        return recent_activity_schema

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

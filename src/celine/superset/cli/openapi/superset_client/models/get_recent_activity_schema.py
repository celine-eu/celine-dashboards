from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GetRecentActivitySchema")


@_attrs_define
class GetRecentActivitySchema:
    """
    Attributes:
        actions (list[str] | Unset):
        distinct (bool | Unset):
        page (float | Unset):
        page_size (float | Unset):
    """

    actions: list[str] | Unset = UNSET
    distinct: bool | Unset = UNSET
    page: float | Unset = UNSET
    page_size: float | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actions: list[str] | Unset = UNSET
        if not isinstance(self.actions, Unset):
            actions = self.actions

        distinct = self.distinct

        page = self.page

        page_size = self.page_size

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if actions is not UNSET:
            field_dict["actions"] = actions
        if distinct is not UNSET:
            field_dict["distinct"] = distinct
        if page is not UNSET:
            field_dict["page"] = page
        if page_size is not UNSET:
            field_dict["page_size"] = page_size

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        actions = cast(list[str], d.pop("actions", UNSET))

        distinct = d.pop("distinct", UNSET)

        page = d.pop("page", UNSET)

        page_size = d.pop("page_size", UNSET)

        get_recent_activity_schema = cls(
            actions=actions,
            distinct=distinct,
            page=page,
            page_size=page_size,
        )

        get_recent_activity_schema.additional_properties = d
        return get_recent_activity_schema

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

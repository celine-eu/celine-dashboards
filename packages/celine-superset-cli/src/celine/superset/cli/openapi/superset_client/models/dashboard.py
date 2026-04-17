from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Dashboard")


@_attrs_define
class Dashboard:
    """
    Attributes:
        dashboard_title (str | Unset):
        id (int | Unset):
        json_metadata (str | Unset):
    """

    dashboard_title: str | Unset = UNSET
    id: int | Unset = UNSET
    json_metadata: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dashboard_title = self.dashboard_title

        id = self.id

        json_metadata = self.json_metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if dashboard_title is not UNSET:
            field_dict["dashboard_title"] = dashboard_title
        if id is not UNSET:
            field_dict["id"] = id
        if json_metadata is not UNSET:
            field_dict["json_metadata"] = json_metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dashboard_title = d.pop("dashboard_title", UNSET)

        id = d.pop("id", UNSET)

        json_metadata = d.pop("json_metadata", UNSET)

        dashboard = cls(
            dashboard_title=dashboard_title,
            id=id,
            json_metadata=json_metadata,
        )

        dashboard.additional_properties = d
        return dashboard

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

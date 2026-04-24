from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dashboard_screenshot_post_schema_data_mask import DashboardScreenshotPostSchemaDataMask


T = TypeVar("T", bound="DashboardScreenshotPostSchema")


@_attrs_define
class DashboardScreenshotPostSchema:
    """
    Attributes:
        active_tabs (list[str] | Unset): A list representing active tabs.
        anchor (str | Unset): A string representing the anchor.
        data_mask (DashboardScreenshotPostSchemaDataMask | Unset): An object representing the data mask.
        url_params (list[Any] | Unset): A list of tuples, each containing two strings.
    """

    active_tabs: list[str] | Unset = UNSET
    anchor: str | Unset = UNSET
    data_mask: DashboardScreenshotPostSchemaDataMask | Unset = UNSET
    url_params: list[Any] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        active_tabs: list[str] | Unset = UNSET
        if not isinstance(self.active_tabs, Unset):
            active_tabs = self.active_tabs

        anchor = self.anchor

        data_mask: dict[str, Any] | Unset = UNSET
        if not isinstance(self.data_mask, Unset):
            data_mask = self.data_mask.to_dict()

        url_params: list[Any] | Unset = UNSET
        if not isinstance(self.url_params, Unset):
            url_params = self.url_params

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if active_tabs is not UNSET:
            field_dict["activeTabs"] = active_tabs
        if anchor is not UNSET:
            field_dict["anchor"] = anchor
        if data_mask is not UNSET:
            field_dict["dataMask"] = data_mask
        if url_params is not UNSET:
            field_dict["urlParams"] = url_params

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard_screenshot_post_schema_data_mask import DashboardScreenshotPostSchemaDataMask

        d = dict(src_dict)
        active_tabs = cast(list[str], d.pop("activeTabs", UNSET))

        anchor = d.pop("anchor", UNSET)

        _data_mask = d.pop("dataMask", UNSET)
        data_mask: DashboardScreenshotPostSchemaDataMask | Unset
        if isinstance(_data_mask, Unset):
            data_mask = UNSET
        else:
            data_mask = DashboardScreenshotPostSchemaDataMask.from_dict(_data_mask)

        url_params = cast(list[Any], d.pop("urlParams", UNSET))

        dashboard_screenshot_post_schema = cls(
            active_tabs=active_tabs,
            anchor=anchor,
            data_mask=data_mask,
            url_params=url_params,
        )

        dashboard_screenshot_post_schema.additional_properties = d
        return dashboard_screenshot_post_schema

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

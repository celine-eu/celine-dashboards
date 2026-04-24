from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DashboardCacheScreenshotResponseSchema")


@_attrs_define
class DashboardCacheScreenshotResponseSchema:
    """
    Attributes:
        cache_key (str | Unset): The cache key
        dashboard_url (str | Unset): The url to render the dashboard
        image_url (str | Unset): The url to fetch the screenshot
        task_status (str | Unset): The status of the async screenshot
        task_updated_at (str | Unset): The timestamp of the last change in status
    """

    cache_key: str | Unset = UNSET
    dashboard_url: str | Unset = UNSET
    image_url: str | Unset = UNSET
    task_status: str | Unset = UNSET
    task_updated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cache_key = self.cache_key

        dashboard_url = self.dashboard_url

        image_url = self.image_url

        task_status = self.task_status

        task_updated_at = self.task_updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cache_key is not UNSET:
            field_dict["cache_key"] = cache_key
        if dashboard_url is not UNSET:
            field_dict["dashboard_url"] = dashboard_url
        if image_url is not UNSET:
            field_dict["image_url"] = image_url
        if task_status is not UNSET:
            field_dict["task_status"] = task_status
        if task_updated_at is not UNSET:
            field_dict["task_updated_at"] = task_updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cache_key = d.pop("cache_key", UNSET)

        dashboard_url = d.pop("dashboard_url", UNSET)

        image_url = d.pop("image_url", UNSET)

        task_status = d.pop("task_status", UNSET)

        task_updated_at = d.pop("task_updated_at", UNSET)

        dashboard_cache_screenshot_response_schema = cls(
            cache_key=cache_key,
            dashboard_url=dashboard_url,
            image_url=image_url,
            task_status=task_status,
            task_updated_at=task_updated_at,
        )

        dashboard_cache_screenshot_response_schema.additional_properties = d
        return dashboard_cache_screenshot_response_schema

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

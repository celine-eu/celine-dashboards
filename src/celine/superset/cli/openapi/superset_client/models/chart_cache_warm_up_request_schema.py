from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartCacheWarmUpRequestSchema")


@_attrs_define
class ChartCacheWarmUpRequestSchema:
    """
    Attributes:
        chart_id (int): The ID of the chart to warm up cache for
        dashboard_id (int | Unset): The ID of the dashboard to get filters for when warming cache
        extra_filters (str | Unset): Extra filters to apply when warming up cache
    """

    chart_id: int
    dashboard_id: int | Unset = UNSET
    extra_filters: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        chart_id = self.chart_id

        dashboard_id = self.dashboard_id

        extra_filters = self.extra_filters

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "chart_id": chart_id,
            }
        )
        if dashboard_id is not UNSET:
            field_dict["dashboard_id"] = dashboard_id
        if extra_filters is not UNSET:
            field_dict["extra_filters"] = extra_filters

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chart_id = d.pop("chart_id")

        dashboard_id = d.pop("dashboard_id", UNSET)

        extra_filters = d.pop("extra_filters", UNSET)

        chart_cache_warm_up_request_schema = cls(
            chart_id=chart_id,
            dashboard_id=dashboard_id,
            extra_filters=extra_filters,
        )

        chart_cache_warm_up_request_schema.additional_properties = d
        return chart_cache_warm_up_request_schema

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

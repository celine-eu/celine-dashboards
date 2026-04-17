from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartCacheWarmUpResponseSingle")


@_attrs_define
class ChartCacheWarmUpResponseSingle:
    """
    Attributes:
        chart_id (int | Unset): The ID of the chart the status belongs to
        viz_error (str | Unset): Error that occurred when warming cache for chart
        viz_status (str | Unset): Status of the underlying query for the viz
    """

    chart_id: int | Unset = UNSET
    viz_error: str | Unset = UNSET
    viz_status: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        chart_id = self.chart_id

        viz_error = self.viz_error

        viz_status = self.viz_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if chart_id is not UNSET:
            field_dict["chart_id"] = chart_id
        if viz_error is not UNSET:
            field_dict["viz_error"] = viz_error
        if viz_status is not UNSET:
            field_dict["viz_status"] = viz_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chart_id = d.pop("chart_id", UNSET)

        viz_error = d.pop("viz_error", UNSET)

        viz_status = d.pop("viz_status", UNSET)

        chart_cache_warm_up_response_single = cls(
            chart_id=chart_id,
            viz_error=viz_error,
            viz_status=viz_status,
        )

        chart_cache_warm_up_response_single.additional_properties = d
        return chart_cache_warm_up_response_single

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

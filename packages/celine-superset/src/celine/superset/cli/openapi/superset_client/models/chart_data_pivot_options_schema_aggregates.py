from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ChartDataPivotOptionsSchemaAggregates")


@_attrs_define
class ChartDataPivotOptionsSchemaAggregates:
    """The keys are the name of the aggregate column to be created, and the values specify the details of how to apply the
    aggregation. If an operator requires additional options, these can be passed here to be unpacked in the operator
    call. The following numpy operators are supported: average, argmin, argmax, cumsum, cumprod, max, mean, median,
    nansum, nanmin, nanmax, nanmean, nanmedian, min, percentile, prod, product, std, sum, var. Any options required by
    the operator can be passed to the `options` object.

    In the example, a new column `first_quantile` is created based on values in the column `my_col` using the
    `percentile` operator with the `q=0.25` parameter.

        Example:
            {'first_quantile': {'column': 'my_col', 'operator': 'percentile', 'options': {'q': 0.25}}}

    """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chart_data_pivot_options_schema_aggregates = cls()

        chart_data_pivot_options_schema_aggregates.additional_properties = d
        return chart_data_pivot_options_schema_aggregates

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

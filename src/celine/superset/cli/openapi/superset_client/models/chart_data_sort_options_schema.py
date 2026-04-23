from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_sort_options_schema_aggregates import ChartDataSortOptionsSchemaAggregates
    from ..models.chart_data_sort_options_schema_columns import ChartDataSortOptionsSchemaColumns


T = TypeVar("T", bound="ChartDataSortOptionsSchema")


@_attrs_define
class ChartDataSortOptionsSchema:
    """
    Attributes:
        columns (ChartDataSortOptionsSchemaColumns): columns by by which to sort. The key specifies the column name,
            value specifies if sorting in ascending order. Example: {'country': True, 'gender': False}.
        aggregates (ChartDataSortOptionsSchemaAggregates | Unset): The keys are the name of the aggregate column to be
            created, and the values specify the details of how to apply the aggregation. If an operator requires additional
            options, these can be passed here to be unpacked in the operator call. The following numpy operators are
            supported: average, argmin, argmax, cumsum, cumprod, max, mean, median, nansum, nanmin, nanmax, nanmean,
            nanmedian, min, percentile, prod, product, std, sum, var. Any options required by the operator can be passed to
            the `options` object.

            In the example, a new column `first_quantile` is created based on values in the column `my_col` using the
            `percentile` operator with the `q=0.25` parameter. Example: {'first_quantile': {'column': 'my_col', 'operator':
            'percentile', 'options': {'q': 0.25}}}.
    """

    columns: ChartDataSortOptionsSchemaColumns
    aggregates: ChartDataSortOptionsSchemaAggregates | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        columns = self.columns.to_dict()

        aggregates: dict[str, Any] | Unset = UNSET
        if not isinstance(self.aggregates, Unset):
            aggregates = self.aggregates.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "columns": columns,
            }
        )
        if aggregates is not UNSET:
            field_dict["aggregates"] = aggregates

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_sort_options_schema_aggregates import ChartDataSortOptionsSchemaAggregates
        from ..models.chart_data_sort_options_schema_columns import ChartDataSortOptionsSchemaColumns

        d = dict(src_dict)
        columns = ChartDataSortOptionsSchemaColumns.from_dict(d.pop("columns"))

        _aggregates = d.pop("aggregates", UNSET)
        aggregates: ChartDataSortOptionsSchemaAggregates | Unset
        if isinstance(_aggregates, Unset):
            aggregates = UNSET
        else:
            aggregates = ChartDataSortOptionsSchemaAggregates.from_dict(_aggregates)

        chart_data_sort_options_schema = cls(
            columns=columns,
            aggregates=aggregates,
        )

        chart_data_sort_options_schema.additional_properties = d
        return chart_data_sort_options_schema

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

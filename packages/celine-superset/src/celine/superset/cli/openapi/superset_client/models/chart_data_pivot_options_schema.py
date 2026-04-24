from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_pivot_options_schema_aggregates import ChartDataPivotOptionsSchemaAggregates


T = TypeVar("T", bound="ChartDataPivotOptionsSchema")


@_attrs_define
class ChartDataPivotOptionsSchema:
    """
    Attributes:
        aggregates (ChartDataPivotOptionsSchemaAggregates | Unset): The keys are the name of the aggregate column to be
            created, and the values specify the details of how to apply the aggregation. If an operator requires additional
            options, these can be passed here to be unpacked in the operator call. The following numpy operators are
            supported: average, argmin, argmax, cumsum, cumprod, max, mean, median, nansum, nanmin, nanmax, nanmean,
            nanmedian, min, percentile, prod, product, std, sum, var. Any options required by the operator can be passed to
            the `options` object.

            In the example, a new column `first_quantile` is created based on values in the column `my_col` using the
            `percentile` operator with the `q=0.25` parameter. Example: {'first_quantile': {'column': 'my_col', 'operator':
            'percentile', 'options': {'q': 0.25}}}.
        column_fill_value (str | Unset): Value to replace missing pivot columns names with.
        columns (list[str] | Unset): Columns to group by on the table columns
        drop_missing_columns (bool | Unset): Do not include columns whose entries are all missing (default: `true`).
        marginal_distribution_name (str | Unset): Name of marginal distribution row/column. (default: `All`)
        marginal_distributions (bool | Unset): Add totals for row/column. (default: `false`)
        metric_fill_value (float | Unset): Value to replace missing values with in aggregate calculations.
    """

    aggregates: ChartDataPivotOptionsSchemaAggregates | Unset = UNSET
    column_fill_value: str | Unset = UNSET
    columns: list[str] | Unset = UNSET
    drop_missing_columns: bool | Unset = UNSET
    marginal_distribution_name: str | Unset = UNSET
    marginal_distributions: bool | Unset = UNSET
    metric_fill_value: float | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        aggregates: dict[str, Any] | Unset = UNSET
        if not isinstance(self.aggregates, Unset):
            aggregates = self.aggregates.to_dict()

        column_fill_value = self.column_fill_value

        columns: list[str] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = self.columns

        drop_missing_columns = self.drop_missing_columns

        marginal_distribution_name = self.marginal_distribution_name

        marginal_distributions = self.marginal_distributions

        metric_fill_value = self.metric_fill_value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if aggregates is not UNSET:
            field_dict["aggregates"] = aggregates
        if column_fill_value is not UNSET:
            field_dict["column_fill_value"] = column_fill_value
        if columns is not UNSET:
            field_dict["columns"] = columns
        if drop_missing_columns is not UNSET:
            field_dict["drop_missing_columns"] = drop_missing_columns
        if marginal_distribution_name is not UNSET:
            field_dict["marginal_distribution_name"] = marginal_distribution_name
        if marginal_distributions is not UNSET:
            field_dict["marginal_distributions"] = marginal_distributions
        if metric_fill_value is not UNSET:
            field_dict["metric_fill_value"] = metric_fill_value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_pivot_options_schema_aggregates import ChartDataPivotOptionsSchemaAggregates

        d = dict(src_dict)
        _aggregates = d.pop("aggregates", UNSET)
        aggregates: ChartDataPivotOptionsSchemaAggregates | Unset
        if isinstance(_aggregates, Unset):
            aggregates = UNSET
        else:
            aggregates = ChartDataPivotOptionsSchemaAggregates.from_dict(_aggregates)

        column_fill_value = d.pop("column_fill_value", UNSET)

        columns = cast(list[str], d.pop("columns", UNSET))

        drop_missing_columns = d.pop("drop_missing_columns", UNSET)

        marginal_distribution_name = d.pop("marginal_distribution_name", UNSET)

        marginal_distributions = d.pop("marginal_distributions", UNSET)

        metric_fill_value = d.pop("metric_fill_value", UNSET)

        chart_data_pivot_options_schema = cls(
            aggregates=aggregates,
            column_fill_value=column_fill_value,
            columns=columns,
            drop_missing_columns=drop_missing_columns,
            marginal_distribution_name=marginal_distribution_name,
            marginal_distributions=marginal_distributions,
            metric_fill_value=metric_fill_value,
        )

        chart_data_pivot_options_schema.additional_properties = d
        return chart_data_pivot_options_schema

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_adhoc_metric_schema_aggregate import (
    ChartDataAdhocMetricSchemaAggregate,
    check_chart_data_adhoc_metric_schema_aggregate,
)
from ..models.chart_data_adhoc_metric_schema_expression_type import (
    ChartDataAdhocMetricSchemaExpressionType,
    check_chart_data_adhoc_metric_schema_expression_type,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_column import ChartDataColumn


T = TypeVar("T", bound="ChartDataAdhocMetricSchema")


@_attrs_define
class ChartDataAdhocMetricSchema:
    """
    Attributes:
        expression_type (ChartDataAdhocMetricSchemaExpressionType): Simple or SQL metric Example: SQL.
        aggregate (ChartDataAdhocMetricSchemaAggregate | Unset): Aggregation operator.Only required for simple
            expression types.
        column (ChartDataColumn | Unset):
        has_custom_label (bool | Unset): When false, the label will be automatically generated based on the aggregate
            expression. When true, a custom label has to be specified. Example: True.
        is_extra (bool | Unset): Indicates if the filter has been added by a filter component as opposed to being a part
            of the original query.
        label (str | Unset): Label for the metric. Is automatically generated unlesshasCustomLabel is true, in which
            case label must be defined. Example: Weighted observations.
        option_name (str | Unset): Unique identifier. Can be any string value, as long as all metrics have a unique
            identifier. If undefined, a random namewill be generated. Example: metric_aec60732-fac0-4b17-b736-93f1a5c93e30.
        sql_expression (str | Unset): The metric as defined by a SQL aggregate expression. Only required for SQL
            expression type. Example: SUM(weight * observations) / SUM(weight).
        time_grain (str | Unset): Optional time grain for temporal filters Example: PT1M.
    """

    expression_type: ChartDataAdhocMetricSchemaExpressionType
    aggregate: ChartDataAdhocMetricSchemaAggregate | Unset = UNSET
    column: ChartDataColumn | Unset = UNSET
    has_custom_label: bool | Unset = UNSET
    is_extra: bool | Unset = UNSET
    label: str | Unset = UNSET
    option_name: str | Unset = UNSET
    sql_expression: str | Unset = UNSET
    time_grain: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        expression_type: str = self.expression_type

        aggregate: str | Unset = UNSET
        if not isinstance(self.aggregate, Unset):
            aggregate = self.aggregate

        column: dict[str, Any] | Unset = UNSET
        if not isinstance(self.column, Unset):
            column = self.column.to_dict()

        has_custom_label = self.has_custom_label

        is_extra = self.is_extra

        label = self.label

        option_name = self.option_name

        sql_expression = self.sql_expression

        time_grain = self.time_grain

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "expressionType": expression_type,
            }
        )
        if aggregate is not UNSET:
            field_dict["aggregate"] = aggregate
        if column is not UNSET:
            field_dict["column"] = column
        if has_custom_label is not UNSET:
            field_dict["hasCustomLabel"] = has_custom_label
        if is_extra is not UNSET:
            field_dict["isExtra"] = is_extra
        if label is not UNSET:
            field_dict["label"] = label
        if option_name is not UNSET:
            field_dict["optionName"] = option_name
        if sql_expression is not UNSET:
            field_dict["sqlExpression"] = sql_expression
        if time_grain is not UNSET:
            field_dict["timeGrain"] = time_grain

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_column import ChartDataColumn

        d = dict(src_dict)
        expression_type = check_chart_data_adhoc_metric_schema_expression_type(d.pop("expressionType"))

        _aggregate = d.pop("aggregate", UNSET)
        aggregate: ChartDataAdhocMetricSchemaAggregate | Unset
        if isinstance(_aggregate, Unset):
            aggregate = UNSET
        else:
            aggregate = check_chart_data_adhoc_metric_schema_aggregate(_aggregate)

        _column = d.pop("column", UNSET)
        column: ChartDataColumn | Unset
        if isinstance(_column, Unset):
            column = UNSET
        else:
            column = ChartDataColumn.from_dict(_column)

        has_custom_label = d.pop("hasCustomLabel", UNSET)

        is_extra = d.pop("isExtra", UNSET)

        label = d.pop("label", UNSET)

        option_name = d.pop("optionName", UNSET)

        sql_expression = d.pop("sqlExpression", UNSET)

        time_grain = d.pop("timeGrain", UNSET)

        chart_data_adhoc_metric_schema = cls(
            expression_type=expression_type,
            aggregate=aggregate,
            column=column,
            has_custom_label=has_custom_label,
            is_extra=is_extra,
            label=label,
            option_name=option_name,
            sql_expression=sql_expression,
            time_grain=time_grain,
        )

        chart_data_adhoc_metric_schema.additional_properties = d
        return chart_data_adhoc_metric_schema

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

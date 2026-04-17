from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_boxplot_options_schema_whisker_type import (
    ChartDataBoxplotOptionsSchemaWhiskerType,
    check_chart_data_boxplot_options_schema_whisker_type,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataBoxplotOptionsSchema")


@_attrs_define
class ChartDataBoxplotOptionsSchema:
    """
    Attributes:
        whisker_type (ChartDataBoxplotOptionsSchemaWhiskerType): Whisker type. Any numpy function will work. Example:
            tukey.
        groupby (list[str] | None | Unset):
        metrics (list[Any] | None | Unset): Aggregate expressions. Metrics can be passed as both references to
            datasource metrics (strings), or ad-hoc metricswhich are defined only within the query object. See
            `ChartDataAdhocMetricSchema` for the structure of ad-hoc metrics. When metrics is undefined or null, the query
            is executed without a groupby. However, when metrics is an array (length >= 0), a groupby clause is added to the
            query.
        percentiles (Any | Unset): Upper and lower percentiles for percentile whisker type. Example: [1, 99].
    """

    whisker_type: ChartDataBoxplotOptionsSchemaWhiskerType
    groupby: list[str] | None | Unset = UNSET
    metrics: list[Any] | None | Unset = UNSET
    percentiles: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        whisker_type: str = self.whisker_type

        groupby: list[str] | None | Unset
        if isinstance(self.groupby, Unset):
            groupby = UNSET
        elif isinstance(self.groupby, list):
            groupby = self.groupby

        else:
            groupby = self.groupby

        metrics: list[Any] | None | Unset
        if isinstance(self.metrics, Unset):
            metrics = UNSET
        elif isinstance(self.metrics, list):
            metrics = self.metrics

        else:
            metrics = self.metrics

        percentiles = self.percentiles

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "whisker_type": whisker_type,
            }
        )
        if groupby is not UNSET:
            field_dict["groupby"] = groupby
        if metrics is not UNSET:
            field_dict["metrics"] = metrics
        if percentiles is not UNSET:
            field_dict["percentiles"] = percentiles

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        whisker_type = check_chart_data_boxplot_options_schema_whisker_type(d.pop("whisker_type"))

        def _parse_groupby(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                groupby_type_0 = cast(list[str], data)

                return groupby_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        groupby = _parse_groupby(d.pop("groupby", UNSET))

        def _parse_metrics(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                metrics_type_0 = cast(list[Any], data)

                return metrics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        metrics = _parse_metrics(d.pop("metrics", UNSET))

        percentiles = d.pop("percentiles", UNSET)

        chart_data_boxplot_options_schema = cls(
            whisker_type=whisker_type,
            groupby=groupby,
            metrics=metrics,
            percentiles=percentiles,
        )

        chart_data_boxplot_options_schema.additional_properties = d
        return chart_data_boxplot_options_schema

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_prophet_options_schema_time_grain import (
    ChartDataProphetOptionsSchemaTimeGrain,
    check_chart_data_prophet_options_schema_time_grain,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataProphetOptionsSchema")


@_attrs_define
class ChartDataProphetOptionsSchema:
    """
    Attributes:
        confidence_interval (float): Width of predicted confidence interval Example: 0.8.
        periods (int): Time periods (in units of `time_grain`) to predict into the future Example: 7.
        time_grain (ChartDataProphetOptionsSchemaTimeGrain): Time grain used to specify time period increments in
            prediction. Supports [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Durations) durations. Example: P1D.
        monthly_seasonality (Any | Unset): Should monthly seasonality be applied. An integer value will specify Fourier
            order of seasonality, `None` will automatically detect seasonality.
        weekly_seasonality (Any | Unset): Should weekly seasonality be applied. An integer value will specify Fourier
            order of seasonality, `None` will automatically detect seasonality.
        yearly_seasonality (Any | Unset): Should yearly seasonality be applied. An integer value will specify Fourier
            order of seasonality, `None` will automatically detect seasonality.
    """

    confidence_interval: float
    periods: int
    time_grain: ChartDataProphetOptionsSchemaTimeGrain
    monthly_seasonality: Any | Unset = UNSET
    weekly_seasonality: Any | Unset = UNSET
    yearly_seasonality: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        confidence_interval = self.confidence_interval

        periods = self.periods

        time_grain: str = self.time_grain

        monthly_seasonality = self.monthly_seasonality

        weekly_seasonality = self.weekly_seasonality

        yearly_seasonality = self.yearly_seasonality

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "confidence_interval": confidence_interval,
                "periods": periods,
                "time_grain": time_grain,
            }
        )
        if monthly_seasonality is not UNSET:
            field_dict["monthly_seasonality"] = monthly_seasonality
        if weekly_seasonality is not UNSET:
            field_dict["weekly_seasonality"] = weekly_seasonality
        if yearly_seasonality is not UNSET:
            field_dict["yearly_seasonality"] = yearly_seasonality

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        confidence_interval = d.pop("confidence_interval")

        periods = d.pop("periods")

        time_grain = check_chart_data_prophet_options_schema_time_grain(d.pop("time_grain"))

        monthly_seasonality = d.pop("monthly_seasonality", UNSET)

        weekly_seasonality = d.pop("weekly_seasonality", UNSET)

        yearly_seasonality = d.pop("yearly_seasonality", UNSET)

        chart_data_prophet_options_schema = cls(
            confidence_interval=confidence_interval,
            periods=periods,
            time_grain=time_grain,
            monthly_seasonality=monthly_seasonality,
            weekly_seasonality=weekly_seasonality,
            yearly_seasonality=yearly_seasonality,
        )

        chart_data_prophet_options_schema.additional_properties = d
        return chart_data_prophet_options_schema

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

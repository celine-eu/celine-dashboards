from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_extras_relative_end import ChartDataExtrasRelativeEnd, check_chart_data_extras_relative_end
from ..models.chart_data_extras_relative_start import (
    ChartDataExtrasRelativeStart,
    check_chart_data_extras_relative_start,
)
from ..models.chart_data_extras_time_grain_sqla_type_1 import (
    ChartDataExtrasTimeGrainSqlaType1,
    check_chart_data_extras_time_grain_sqla_type_1,
)
from ..models.chart_data_extras_time_grain_sqla_type_2_type_1 import (
    ChartDataExtrasTimeGrainSqlaType2Type1,
    check_chart_data_extras_time_grain_sqla_type_2_type_1,
)
from ..models.chart_data_extras_time_grain_sqla_type_3_type_1 import (
    ChartDataExtrasTimeGrainSqlaType3Type1,
    check_chart_data_extras_time_grain_sqla_type_3_type_1,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataExtras")


@_attrs_define
class ChartDataExtras:
    """
    Attributes:
        having (str | Unset): HAVING clause to be added to aggregate queries using AND operator.
        instant_time_comparison_range (None | str | Unset): This is only set using the new time comparison controls that
            is made available in some plugins behind the experimental feature flag.
        relative_end (ChartDataExtrasRelativeEnd | Unset): End time for relative time deltas. Default:
            `config["DEFAULT_RELATIVE_START_TIME"]`
        relative_start (ChartDataExtrasRelativeStart | Unset): Start time for relative time deltas. Default:
            `config["DEFAULT_RELATIVE_START_TIME"]`
        time_grain_sqla (ChartDataExtrasTimeGrainSqlaType1 | ChartDataExtrasTimeGrainSqlaType2Type1 |
            ChartDataExtrasTimeGrainSqlaType3Type1 | None | Unset): To what level of granularity should the temporal column
            be aggregated. Supports [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Durations) durations. Example: P1D.
        where (str | Unset): WHERE clause to be added to queries using AND operator.
    """

    having: str | Unset = UNSET
    instant_time_comparison_range: None | str | Unset = UNSET
    relative_end: ChartDataExtrasRelativeEnd | Unset = UNSET
    relative_start: ChartDataExtrasRelativeStart | Unset = UNSET
    time_grain_sqla: (
        ChartDataExtrasTimeGrainSqlaType1
        | ChartDataExtrasTimeGrainSqlaType2Type1
        | ChartDataExtrasTimeGrainSqlaType3Type1
        | None
        | Unset
    ) = UNSET
    where: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        having = self.having

        instant_time_comparison_range: None | str | Unset
        if isinstance(self.instant_time_comparison_range, Unset):
            instant_time_comparison_range = UNSET
        else:
            instant_time_comparison_range = self.instant_time_comparison_range

        relative_end: str | Unset = UNSET
        if not isinstance(self.relative_end, Unset):
            relative_end = self.relative_end

        relative_start: str | Unset = UNSET
        if not isinstance(self.relative_start, Unset):
            relative_start = self.relative_start

        time_grain_sqla: None | str | Unset
        if isinstance(self.time_grain_sqla, Unset):
            time_grain_sqla = UNSET
        elif isinstance(self.time_grain_sqla, str):
            time_grain_sqla = self.time_grain_sqla
        elif isinstance(self.time_grain_sqla, str):
            time_grain_sqla = self.time_grain_sqla
        elif isinstance(self.time_grain_sqla, str):
            time_grain_sqla = self.time_grain_sqla
        else:
            time_grain_sqla = self.time_grain_sqla

        where = self.where

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if having is not UNSET:
            field_dict["having"] = having
        if instant_time_comparison_range is not UNSET:
            field_dict["instant_time_comparison_range"] = instant_time_comparison_range
        if relative_end is not UNSET:
            field_dict["relative_end"] = relative_end
        if relative_start is not UNSET:
            field_dict["relative_start"] = relative_start
        if time_grain_sqla is not UNSET:
            field_dict["time_grain_sqla"] = time_grain_sqla
        if where is not UNSET:
            field_dict["where"] = where

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        having = d.pop("having", UNSET)

        def _parse_instant_time_comparison_range(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        instant_time_comparison_range = _parse_instant_time_comparison_range(
            d.pop("instant_time_comparison_range", UNSET)
        )

        _relative_end = d.pop("relative_end", UNSET)
        relative_end: ChartDataExtrasRelativeEnd | Unset
        if isinstance(_relative_end, Unset):
            relative_end = UNSET
        else:
            relative_end = check_chart_data_extras_relative_end(_relative_end)

        _relative_start = d.pop("relative_start", UNSET)
        relative_start: ChartDataExtrasRelativeStart | Unset
        if isinstance(_relative_start, Unset):
            relative_start = UNSET
        else:
            relative_start = check_chart_data_extras_relative_start(_relative_start)

        def _parse_time_grain_sqla(
            data: object,
        ) -> (
            ChartDataExtrasTimeGrainSqlaType1
            | ChartDataExtrasTimeGrainSqlaType2Type1
            | ChartDataExtrasTimeGrainSqlaType3Type1
            | None
            | Unset
        ):
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                time_grain_sqla_type_1 = check_chart_data_extras_time_grain_sqla_type_1(data)

                return time_grain_sqla_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, str):
                    raise TypeError()
                time_grain_sqla_type_2_type_1 = check_chart_data_extras_time_grain_sqla_type_2_type_1(data)

                return time_grain_sqla_type_2_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, str):
                    raise TypeError()
                time_grain_sqla_type_3_type_1 = check_chart_data_extras_time_grain_sqla_type_3_type_1(data)

                return time_grain_sqla_type_3_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(
                ChartDataExtrasTimeGrainSqlaType1
                | ChartDataExtrasTimeGrainSqlaType2Type1
                | ChartDataExtrasTimeGrainSqlaType3Type1
                | None
                | Unset,
                data,
            )

        time_grain_sqla = _parse_time_grain_sqla(d.pop("time_grain_sqla", UNSET))

        where = d.pop("where", UNSET)

        chart_data_extras = cls(
            having=having,
            instant_time_comparison_range=instant_time_comparison_range,
            relative_end=relative_end,
            relative_start=relative_start,
            time_grain_sqla=time_grain_sqla,
            where=where,
        )

        chart_data_extras.additional_properties = d
        return chart_data_extras

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

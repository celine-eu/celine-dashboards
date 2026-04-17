from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_rolling_options_schema_rolling_type import (
    ChartDataRollingOptionsSchemaRollingType,
    check_chart_data_rolling_options_schema_rolling_type,
)
from ..models.chart_data_rolling_options_schema_win_type import (
    ChartDataRollingOptionsSchemaWinType,
    check_chart_data_rolling_options_schema_win_type,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_rolling_options_schema_rolling_type_options import (
        ChartDataRollingOptionsSchemaRollingTypeOptions,
    )


T = TypeVar("T", bound="ChartDataRollingOptionsSchema")


@_attrs_define
class ChartDataRollingOptionsSchema:
    """
    Attributes:
        rolling_type (ChartDataRollingOptionsSchemaRollingType): Type of rolling window. Any numpy function will work.
            Example: percentile.
        window (int): Size of the rolling window in days. Example: 7.
        center (bool | Unset): Should the label be at the center of the window.Default: `false`
        min_periods (int | Unset): The minimum amount of periods required for a row to be included in the result set.
            Example: 7.
        rolling_type_options (ChartDataRollingOptionsSchemaRollingTypeOptions | Unset): Optional options to pass to
            rolling method. Needed for e.g. quantile operation.
        win_type (ChartDataRollingOptionsSchemaWinType | Unset): Type of window function. See [SciPy window
            functions](https://docs.scipy.org/doc/scipy/reference /signal.windows.html#module-scipy.signal.windows) for more
            details. Some window functions require passing additional parameters to `rolling_type_options`. For instance, to
            use `gaussian`, the parameter `std` needs to be provided.
    """

    rolling_type: ChartDataRollingOptionsSchemaRollingType
    window: int
    center: bool | Unset = UNSET
    min_periods: int | Unset = UNSET
    rolling_type_options: ChartDataRollingOptionsSchemaRollingTypeOptions | Unset = UNSET
    win_type: ChartDataRollingOptionsSchemaWinType | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rolling_type: str = self.rolling_type

        window = self.window

        center = self.center

        min_periods = self.min_periods

        rolling_type_options: dict[str, Any] | Unset = UNSET
        if not isinstance(self.rolling_type_options, Unset):
            rolling_type_options = self.rolling_type_options.to_dict()

        win_type: str | Unset = UNSET
        if not isinstance(self.win_type, Unset):
            win_type = self.win_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rolling_type": rolling_type,
                "window": window,
            }
        )
        if center is not UNSET:
            field_dict["center"] = center
        if min_periods is not UNSET:
            field_dict["min_periods"] = min_periods
        if rolling_type_options is not UNSET:
            field_dict["rolling_type_options"] = rolling_type_options
        if win_type is not UNSET:
            field_dict["win_type"] = win_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_rolling_options_schema_rolling_type_options import (
            ChartDataRollingOptionsSchemaRollingTypeOptions,
        )

        d = dict(src_dict)
        rolling_type = check_chart_data_rolling_options_schema_rolling_type(d.pop("rolling_type"))

        window = d.pop("window")

        center = d.pop("center", UNSET)

        min_periods = d.pop("min_periods", UNSET)

        _rolling_type_options = d.pop("rolling_type_options", UNSET)
        rolling_type_options: ChartDataRollingOptionsSchemaRollingTypeOptions | Unset
        if isinstance(_rolling_type_options, Unset):
            rolling_type_options = UNSET
        else:
            rolling_type_options = ChartDataRollingOptionsSchemaRollingTypeOptions.from_dict(_rolling_type_options)

        _win_type = d.pop("win_type", UNSET)
        win_type: ChartDataRollingOptionsSchemaWinType | Unset
        if isinstance(_win_type, Unset):
            win_type = UNSET
        else:
            win_type = check_chart_data_rolling_options_schema_win_type(_win_type)

        chart_data_rolling_options_schema = cls(
            rolling_type=rolling_type,
            window=window,
            center=center,
            min_periods=min_periods,
            rolling_type_options=rolling_type_options,
            win_type=win_type,
        )

        chart_data_rolling_options_schema.additional_properties = d
        return chart_data_rolling_options_schema

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

from typing import Literal, cast

ChartDataExtrasRelativeStart = Literal["now", "today"]

CHART_DATA_EXTRAS_RELATIVE_START_VALUES: set[ChartDataExtrasRelativeStart] = {
    "now",
    "today",
}


def check_chart_data_extras_relative_start(value: str) -> ChartDataExtrasRelativeStart:
    if value in CHART_DATA_EXTRAS_RELATIVE_START_VALUES:
        return cast(ChartDataExtrasRelativeStart, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_EXTRAS_RELATIVE_START_VALUES!r}")

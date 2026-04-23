from typing import Literal, cast

ChartDataExtrasRelativeEnd = Literal["now", "today"]

CHART_DATA_EXTRAS_RELATIVE_END_VALUES: set[ChartDataExtrasRelativeEnd] = {
    "now",
    "today",
}


def check_chart_data_extras_relative_end(value: str) -> ChartDataExtrasRelativeEnd:
    if value in CHART_DATA_EXTRAS_RELATIVE_END_VALUES:
        return cast(ChartDataExtrasRelativeEnd, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_EXTRAS_RELATIVE_END_VALUES!r}")

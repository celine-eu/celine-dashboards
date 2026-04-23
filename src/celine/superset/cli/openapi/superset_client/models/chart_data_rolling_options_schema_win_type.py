from typing import Literal, cast

ChartDataRollingOptionsSchemaWinType = Literal[
    "barthann",
    "bartlett",
    "blackman",
    "blackmanharris",
    "bohman",
    "boxcar",
    "exponential",
    "gaussian",
    "general_gaussian",
    "hamming",
    "kaiser",
    "nuttall",
    "parzen",
    "slepian",
    "triang",
]

CHART_DATA_ROLLING_OPTIONS_SCHEMA_WIN_TYPE_VALUES: set[ChartDataRollingOptionsSchemaWinType] = {
    "barthann",
    "bartlett",
    "blackman",
    "blackmanharris",
    "bohman",
    "boxcar",
    "exponential",
    "gaussian",
    "general_gaussian",
    "hamming",
    "kaiser",
    "nuttall",
    "parzen",
    "slepian",
    "triang",
}


def check_chart_data_rolling_options_schema_win_type(value: str) -> ChartDataRollingOptionsSchemaWinType:
    if value in CHART_DATA_ROLLING_OPTIONS_SCHEMA_WIN_TYPE_VALUES:
        return cast(ChartDataRollingOptionsSchemaWinType, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_ROLLING_OPTIONS_SCHEMA_WIN_TYPE_VALUES!r}"
    )

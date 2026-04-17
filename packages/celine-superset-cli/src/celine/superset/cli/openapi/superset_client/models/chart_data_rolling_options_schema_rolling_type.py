from typing import Literal, cast

ChartDataRollingOptionsSchemaRollingType = Literal[
    "argmax",
    "argmin",
    "average",
    "cumprod",
    "cumsum",
    "max",
    "mean",
    "median",
    "min",
    "nanmax",
    "nanmean",
    "nanmedian",
    "nanmin",
    "nanpercentile",
    "nansum",
    "percentile",
    "prod",
    "product",
    "std",
    "sum",
    "var",
]

CHART_DATA_ROLLING_OPTIONS_SCHEMA_ROLLING_TYPE_VALUES: set[ChartDataRollingOptionsSchemaRollingType] = {
    "argmax",
    "argmin",
    "average",
    "cumprod",
    "cumsum",
    "max",
    "mean",
    "median",
    "min",
    "nanmax",
    "nanmean",
    "nanmedian",
    "nanmin",
    "nanpercentile",
    "nansum",
    "percentile",
    "prod",
    "product",
    "std",
    "sum",
    "var",
}


def check_chart_data_rolling_options_schema_rolling_type(value: str) -> ChartDataRollingOptionsSchemaRollingType:
    if value in CHART_DATA_ROLLING_OPTIONS_SCHEMA_ROLLING_TYPE_VALUES:
        return cast(ChartDataRollingOptionsSchemaRollingType, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_ROLLING_OPTIONS_SCHEMA_ROLLING_TYPE_VALUES!r}"
    )

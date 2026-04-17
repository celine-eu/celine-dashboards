from typing import Literal, cast

ChartDataProphetOptionsSchemaTimeGrain = Literal[
    "1969-12-28T00:00:00Z/P1W",
    "1969-12-29T00:00:00Z/P1W",
    "P1D",
    "P1M",
    "P1W",
    "P1W/1970-01-03T00:00:00Z",
    "P1W/1970-01-04T00:00:00Z",
    "P1Y",
    "P3M",
    "PT10M",
    "PT15M",
    "PT1H",
    "PT1M",
    "PT1S",
    "PT30M",
    "PT30S",
    "PT5M",
    "PT5S",
    "PT6H",
]

CHART_DATA_PROPHET_OPTIONS_SCHEMA_TIME_GRAIN_VALUES: set[ChartDataProphetOptionsSchemaTimeGrain] = {
    "1969-12-28T00:00:00Z/P1W",
    "1969-12-29T00:00:00Z/P1W",
    "P1D",
    "P1M",
    "P1W",
    "P1W/1970-01-03T00:00:00Z",
    "P1W/1970-01-04T00:00:00Z",
    "P1Y",
    "P3M",
    "PT10M",
    "PT15M",
    "PT1H",
    "PT1M",
    "PT1S",
    "PT30M",
    "PT30S",
    "PT5M",
    "PT5S",
    "PT6H",
}


def check_chart_data_prophet_options_schema_time_grain(value: str) -> ChartDataProphetOptionsSchemaTimeGrain:
    if value in CHART_DATA_PROPHET_OPTIONS_SCHEMA_TIME_GRAIN_VALUES:
        return cast(ChartDataProphetOptionsSchemaTimeGrain, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_PROPHET_OPTIONS_SCHEMA_TIME_GRAIN_VALUES!r}"
    )

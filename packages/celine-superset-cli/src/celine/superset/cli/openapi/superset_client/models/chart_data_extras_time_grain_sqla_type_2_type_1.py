from typing import Literal, cast

ChartDataExtrasTimeGrainSqlaType2Type1 = Literal[
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

CHART_DATA_EXTRAS_TIME_GRAIN_SQLA_TYPE_2_TYPE_1_VALUES: set[ChartDataExtrasTimeGrainSqlaType2Type1] = {
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


def check_chart_data_extras_time_grain_sqla_type_2_type_1(value: str) -> ChartDataExtrasTimeGrainSqlaType2Type1:
    if value in CHART_DATA_EXTRAS_TIME_GRAIN_SQLA_TYPE_2_TYPE_1_VALUES:
        return cast(ChartDataExtrasTimeGrainSqlaType2Type1, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_EXTRAS_TIME_GRAIN_SQLA_TYPE_2_TYPE_1_VALUES!r}"
    )

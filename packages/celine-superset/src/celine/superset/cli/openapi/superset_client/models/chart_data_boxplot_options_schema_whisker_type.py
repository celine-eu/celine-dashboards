from typing import Literal, cast

ChartDataBoxplotOptionsSchemaWhiskerType = Literal["min/max", "percentile", "tukey"]

CHART_DATA_BOXPLOT_OPTIONS_SCHEMA_WHISKER_TYPE_VALUES: set[ChartDataBoxplotOptionsSchemaWhiskerType] = {
    "min/max",
    "percentile",
    "tukey",
}


def check_chart_data_boxplot_options_schema_whisker_type(value: str) -> ChartDataBoxplotOptionsSchemaWhiskerType:
    if value in CHART_DATA_BOXPLOT_OPTIONS_SCHEMA_WHISKER_TYPE_VALUES:
        return cast(ChartDataBoxplotOptionsSchemaWhiskerType, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_BOXPLOT_OPTIONS_SCHEMA_WHISKER_TYPE_VALUES!r}"
    )

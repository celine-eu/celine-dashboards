from typing import Literal, cast

ChartDataQueryContextSchemaResultFormat = Literal["csv", "json", "xlsx"]

CHART_DATA_QUERY_CONTEXT_SCHEMA_RESULT_FORMAT_VALUES: set[ChartDataQueryContextSchemaResultFormat] = {
    "csv",
    "json",
    "xlsx",
}


def check_chart_data_query_context_schema_result_format(value: str) -> ChartDataQueryContextSchemaResultFormat:
    if value in CHART_DATA_QUERY_CONTEXT_SCHEMA_RESULT_FORMAT_VALUES:
        return cast(ChartDataQueryContextSchemaResultFormat, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_QUERY_CONTEXT_SCHEMA_RESULT_FORMAT_VALUES!r}"
    )

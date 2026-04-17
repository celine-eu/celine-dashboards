from typing import Literal, cast

ChartDataQueryContextSchemaResultType = Literal[
    "columns", "drill_detail", "full", "post_processed", "query", "results", "samples", "timegrains"
]

CHART_DATA_QUERY_CONTEXT_SCHEMA_RESULT_TYPE_VALUES: set[ChartDataQueryContextSchemaResultType] = {
    "columns",
    "drill_detail",
    "full",
    "post_processed",
    "query",
    "results",
    "samples",
    "timegrains",
}


def check_chart_data_query_context_schema_result_type(value: str) -> ChartDataQueryContextSchemaResultType:
    if value in CHART_DATA_QUERY_CONTEXT_SCHEMA_RESULT_TYPE_VALUES:
        return cast(ChartDataQueryContextSchemaResultType, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_QUERY_CONTEXT_SCHEMA_RESULT_TYPE_VALUES!r}"
    )

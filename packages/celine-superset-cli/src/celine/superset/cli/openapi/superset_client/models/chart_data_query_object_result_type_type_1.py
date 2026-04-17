from typing import Literal, cast

ChartDataQueryObjectResultTypeType1 = Literal[
    "columns", "drill_detail", "full", "post_processed", "query", "results", "samples", "timegrains"
]

CHART_DATA_QUERY_OBJECT_RESULT_TYPE_TYPE_1_VALUES: set[ChartDataQueryObjectResultTypeType1] = {
    "columns",
    "drill_detail",
    "full",
    "post_processed",
    "query",
    "results",
    "samples",
    "timegrains",
}


def check_chart_data_query_object_result_type_type_1(value: str) -> ChartDataQueryObjectResultTypeType1:
    if value in CHART_DATA_QUERY_OBJECT_RESULT_TYPE_TYPE_1_VALUES:
        return cast(ChartDataQueryObjectResultTypeType1, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_QUERY_OBJECT_RESULT_TYPE_TYPE_1_VALUES!r}"
    )

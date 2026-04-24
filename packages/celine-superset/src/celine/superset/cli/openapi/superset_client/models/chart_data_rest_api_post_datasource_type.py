from typing import Literal, cast

ChartDataRestApiPostDatasourceType = Literal["dataset", "query", "saved_query", "table", "view"]

CHART_DATA_REST_API_POST_DATASOURCE_TYPE_VALUES: set[ChartDataRestApiPostDatasourceType] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_chart_data_rest_api_post_datasource_type(value: str) -> ChartDataRestApiPostDatasourceType:
    if value in CHART_DATA_REST_API_POST_DATASOURCE_TYPE_VALUES:
        return cast(ChartDataRestApiPostDatasourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_REST_API_POST_DATASOURCE_TYPE_VALUES!r}")

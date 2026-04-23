from typing import Literal, cast

ChartRestApiPostDatasourceType = Literal["dataset", "query", "saved_query", "table", "view"]

CHART_REST_API_POST_DATASOURCE_TYPE_VALUES: set[ChartRestApiPostDatasourceType] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_chart_rest_api_post_datasource_type(value: str) -> ChartRestApiPostDatasourceType:
    if value in CHART_REST_API_POST_DATASOURCE_TYPE_VALUES:
        return cast(ChartRestApiPostDatasourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_REST_API_POST_DATASOURCE_TYPE_VALUES!r}")

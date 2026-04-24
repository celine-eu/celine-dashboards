from typing import Literal, cast

ChartDataRestApiPutDatasourceTypeType1 = Literal["dataset", "query", "saved_query", "table", "view"]

CHART_DATA_REST_API_PUT_DATASOURCE_TYPE_TYPE_1_VALUES: set[ChartDataRestApiPutDatasourceTypeType1] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_chart_data_rest_api_put_datasource_type_type_1(value: str) -> ChartDataRestApiPutDatasourceTypeType1:
    if value in CHART_DATA_REST_API_PUT_DATASOURCE_TYPE_TYPE_1_VALUES:
        return cast(ChartDataRestApiPutDatasourceTypeType1, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_REST_API_PUT_DATASOURCE_TYPE_TYPE_1_VALUES!r}"
    )

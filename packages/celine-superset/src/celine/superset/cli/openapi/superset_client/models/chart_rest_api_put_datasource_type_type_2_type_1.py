from typing import Literal, cast

ChartRestApiPutDatasourceTypeType2Type1 = Literal["dataset", "query", "saved_query", "table", "view"]

CHART_REST_API_PUT_DATASOURCE_TYPE_TYPE_2_TYPE_1_VALUES: set[ChartRestApiPutDatasourceTypeType2Type1] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_chart_rest_api_put_datasource_type_type_2_type_1(value: str) -> ChartRestApiPutDatasourceTypeType2Type1:
    if value in CHART_REST_API_PUT_DATASOURCE_TYPE_TYPE_2_TYPE_1_VALUES:
        return cast(ChartRestApiPutDatasourceTypeType2Type1, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_REST_API_PUT_DATASOURCE_TYPE_TYPE_2_TYPE_1_VALUES!r}"
    )

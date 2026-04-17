from typing import Literal, cast

ChartDataDatasourceType = Literal["dataset", "query", "saved_query", "table", "view"]

CHART_DATA_DATASOURCE_TYPE_VALUES: set[ChartDataDatasourceType] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_chart_data_datasource_type(value: str) -> ChartDataDatasourceType:
    if value in CHART_DATA_DATASOURCE_TYPE_VALUES:
        return cast(ChartDataDatasourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_DATASOURCE_TYPE_VALUES!r}")

from typing import Literal, cast

DatasourceDatasourceType = Literal["dataset", "query", "saved_query", "table", "view"]

DATASOURCE_DATASOURCE_TYPE_VALUES: set[DatasourceDatasourceType] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_datasource_datasource_type(value: str) -> DatasourceDatasourceType:
    if value in DATASOURCE_DATASOURCE_TYPE_VALUES:
        return cast(DatasourceDatasourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {DATASOURCE_DATASOURCE_TYPE_VALUES!r}")

from typing import Literal, cast

ChartDataRestApiGetListTagType = Literal[1, 2, 3, 4]

CHART_DATA_REST_API_GET_LIST_TAG_TYPE_VALUES: set[ChartDataRestApiGetListTagType] = {
    1,
    2,
    3,
    4,
}


def check_chart_data_rest_api_get_list_tag_type(value: int) -> ChartDataRestApiGetListTagType:
    if value in CHART_DATA_REST_API_GET_LIST_TAG_TYPE_VALUES:
        return cast(ChartDataRestApiGetListTagType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_REST_API_GET_LIST_TAG_TYPE_VALUES!r}")

from typing import Literal, cast

ChartRestApiGetListTagType = Literal[1, 2, 3, 4]

CHART_REST_API_GET_LIST_TAG_TYPE_VALUES: set[ChartRestApiGetListTagType] = {
    1,
    2,
    3,
    4,
}


def check_chart_rest_api_get_list_tag_type(value: int) -> ChartRestApiGetListTagType:
    if value in CHART_REST_API_GET_LIST_TAG_TYPE_VALUES:
        return cast(ChartRestApiGetListTagType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_REST_API_GET_LIST_TAG_TYPE_VALUES!r}")

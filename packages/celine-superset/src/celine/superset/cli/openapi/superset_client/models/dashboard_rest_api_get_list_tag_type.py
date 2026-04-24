from typing import Literal, cast

DashboardRestApiGetListTagType = Literal[1, 2, 3, 4]

DASHBOARD_REST_API_GET_LIST_TAG_TYPE_VALUES: set[DashboardRestApiGetListTagType] = {
    1,
    2,
    3,
    4,
}


def check_dashboard_rest_api_get_list_tag_type(value: int) -> DashboardRestApiGetListTagType:
    if value in DASHBOARD_REST_API_GET_LIST_TAG_TYPE_VALUES:
        return cast(DashboardRestApiGetListTagType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {DASHBOARD_REST_API_GET_LIST_TAG_TYPE_VALUES!r}")

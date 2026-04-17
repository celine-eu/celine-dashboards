from typing import Literal, cast

GetApiV1SecurityRolesSearchQFiltersItemCol = Literal["name", "permission_ids", "user_ids"]

GET_API_V1_SECURITY_ROLES_SEARCH_Q_FILTERS_ITEM_COL_VALUES: set[GetApiV1SecurityRolesSearchQFiltersItemCol] = {
    "name",
    "permission_ids",
    "user_ids",
}


def check_get_api_v1_security_roles_search_q_filters_item_col(value: str) -> GetApiV1SecurityRolesSearchQFiltersItemCol:
    if value in GET_API_V1_SECURITY_ROLES_SEARCH_Q_FILTERS_ITEM_COL_VALUES:
        return cast(GetApiV1SecurityRolesSearchQFiltersItemCol, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {GET_API_V1_SECURITY_ROLES_SEARCH_Q_FILTERS_ITEM_COL_VALUES!r}"
    )

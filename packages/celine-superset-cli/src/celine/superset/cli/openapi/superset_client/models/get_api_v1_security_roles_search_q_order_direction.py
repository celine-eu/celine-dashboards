from typing import Literal, cast

GetApiV1SecurityRolesSearchQOrderDirection = Literal["asc", "desc"]

GET_API_V1_SECURITY_ROLES_SEARCH_Q_ORDER_DIRECTION_VALUES: set[GetApiV1SecurityRolesSearchQOrderDirection] = {
    "asc",
    "desc",
}


def check_get_api_v1_security_roles_search_q_order_direction(value: str) -> GetApiV1SecurityRolesSearchQOrderDirection:
    if value in GET_API_V1_SECURITY_ROLES_SEARCH_Q_ORDER_DIRECTION_VALUES:
        return cast(GetApiV1SecurityRolesSearchQOrderDirection, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {GET_API_V1_SECURITY_ROLES_SEARCH_Q_ORDER_DIRECTION_VALUES!r}"
    )

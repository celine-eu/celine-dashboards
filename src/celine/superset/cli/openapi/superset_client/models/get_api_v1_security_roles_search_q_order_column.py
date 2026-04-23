from typing import Literal, cast

GetApiV1SecurityRolesSearchQOrderColumn = Literal["id", "name"]

GET_API_V1_SECURITY_ROLES_SEARCH_Q_ORDER_COLUMN_VALUES: set[GetApiV1SecurityRolesSearchQOrderColumn] = {
    "id",
    "name",
}


def check_get_api_v1_security_roles_search_q_order_column(value: str) -> GetApiV1SecurityRolesSearchQOrderColumn:
    if value in GET_API_V1_SECURITY_ROLES_SEARCH_Q_ORDER_COLUMN_VALUES:
        return cast(GetApiV1SecurityRolesSearchQOrderColumn, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {GET_API_V1_SECURITY_ROLES_SEARCH_Q_ORDER_COLUMN_VALUES!r}"
    )

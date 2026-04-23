from typing import Literal, cast

GetApiV1SqllabResultsResponse410ErrorsItemLevel = Literal["error", "info", "warning"]

GET_API_V1_SQLLAB_RESULTS_RESPONSE_410_ERRORS_ITEM_LEVEL_VALUES: set[
    GetApiV1SqllabResultsResponse410ErrorsItemLevel
] = {
    "error",
    "info",
    "warning",
}


def check_get_api_v1_sqllab_results_response_410_errors_item_level(
    value: str,
) -> GetApiV1SqllabResultsResponse410ErrorsItemLevel:
    if value in GET_API_V1_SQLLAB_RESULTS_RESPONSE_410_ERRORS_ITEM_LEVEL_VALUES:
        return cast(GetApiV1SqllabResultsResponse410ErrorsItemLevel, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {GET_API_V1_SQLLAB_RESULTS_RESPONSE_410_ERRORS_ITEM_LEVEL_VALUES!r}"
    )

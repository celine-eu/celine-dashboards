from typing import Literal, cast

DatabaseRestApiPostConfigurationMethod = Literal["dynamic_form", "sqlalchemy_form"]

DATABASE_REST_API_POST_CONFIGURATION_METHOD_VALUES: set[DatabaseRestApiPostConfigurationMethod] = {
    "dynamic_form",
    "sqlalchemy_form",
}


def check_database_rest_api_post_configuration_method(value: str) -> DatabaseRestApiPostConfigurationMethod:
    if value in DATABASE_REST_API_POST_CONFIGURATION_METHOD_VALUES:
        return cast(DatabaseRestApiPostConfigurationMethod, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {DATABASE_REST_API_POST_CONFIGURATION_METHOD_VALUES!r}"
    )

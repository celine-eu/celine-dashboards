from typing import Literal, cast

DatabaseRestApiPutConfigurationMethod = Literal["dynamic_form", "sqlalchemy_form"]

DATABASE_REST_API_PUT_CONFIGURATION_METHOD_VALUES: set[DatabaseRestApiPutConfigurationMethod] = {
    "dynamic_form",
    "sqlalchemy_form",
}


def check_database_rest_api_put_configuration_method(value: str) -> DatabaseRestApiPutConfigurationMethod:
    if value in DATABASE_REST_API_PUT_CONFIGURATION_METHOD_VALUES:
        return cast(DatabaseRestApiPutConfigurationMethod, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {DATABASE_REST_API_PUT_CONFIGURATION_METHOD_VALUES!r}"
    )

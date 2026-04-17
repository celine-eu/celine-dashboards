from typing import Literal, cast

DatabaseTestConnectionSchemaConfigurationMethod = Literal["dynamic_form", "sqlalchemy_form"]

DATABASE_TEST_CONNECTION_SCHEMA_CONFIGURATION_METHOD_VALUES: set[DatabaseTestConnectionSchemaConfigurationMethod] = {
    "dynamic_form",
    "sqlalchemy_form",
}


def check_database_test_connection_schema_configuration_method(
    value: str,
) -> DatabaseTestConnectionSchemaConfigurationMethod:
    if value in DATABASE_TEST_CONNECTION_SCHEMA_CONFIGURATION_METHOD_VALUES:
        return cast(DatabaseTestConnectionSchemaConfigurationMethod, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {DATABASE_TEST_CONNECTION_SCHEMA_CONFIGURATION_METHOD_VALUES!r}"
    )

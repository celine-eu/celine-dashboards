from typing import Literal, cast

DatabaseValidateParametersSchemaConfigurationMethod = Literal["dynamic_form", "sqlalchemy_form"]

DATABASE_VALIDATE_PARAMETERS_SCHEMA_CONFIGURATION_METHOD_VALUES: set[
    DatabaseValidateParametersSchemaConfigurationMethod
] = {
    "dynamic_form",
    "sqlalchemy_form",
}


def check_database_validate_parameters_schema_configuration_method(
    value: str,
) -> DatabaseValidateParametersSchemaConfigurationMethod:
    if value in DATABASE_VALIDATE_PARAMETERS_SCHEMA_CONFIGURATION_METHOD_VALUES:
        return cast(DatabaseValidateParametersSchemaConfigurationMethod, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {DATABASE_VALIDATE_PARAMETERS_SCHEMA_CONFIGURATION_METHOD_VALUES!r}"
    )

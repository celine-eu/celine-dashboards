from typing import Literal, cast

ChartDataContributionOptionsSchemaOrientation = Literal["column", "row"]

CHART_DATA_CONTRIBUTION_OPTIONS_SCHEMA_ORIENTATION_VALUES: set[ChartDataContributionOptionsSchemaOrientation] = {
    "column",
    "row",
}


def check_chart_data_contribution_options_schema_orientation(
    value: str,
) -> ChartDataContributionOptionsSchemaOrientation:
    if value in CHART_DATA_CONTRIBUTION_OPTIONS_SCHEMA_ORIENTATION_VALUES:
        return cast(ChartDataContributionOptionsSchemaOrientation, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_CONTRIBUTION_OPTIONS_SCHEMA_ORIENTATION_VALUES!r}"
    )

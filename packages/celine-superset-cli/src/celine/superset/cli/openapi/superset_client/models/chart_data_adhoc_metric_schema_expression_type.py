from typing import Literal, cast

ChartDataAdhocMetricSchemaExpressionType = Literal["SIMPLE", "SQL"]

CHART_DATA_ADHOC_METRIC_SCHEMA_EXPRESSION_TYPE_VALUES: set[ChartDataAdhocMetricSchemaExpressionType] = {
    "SIMPLE",
    "SQL",
}


def check_chart_data_adhoc_metric_schema_expression_type(value: str) -> ChartDataAdhocMetricSchemaExpressionType:
    if value in CHART_DATA_ADHOC_METRIC_SCHEMA_EXPRESSION_TYPE_VALUES:
        return cast(ChartDataAdhocMetricSchemaExpressionType, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_ADHOC_METRIC_SCHEMA_EXPRESSION_TYPE_VALUES!r}"
    )

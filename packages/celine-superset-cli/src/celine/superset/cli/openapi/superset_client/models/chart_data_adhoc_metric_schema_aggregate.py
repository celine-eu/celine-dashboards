from typing import Literal, cast

ChartDataAdhocMetricSchemaAggregate = Literal["AVG", "COUNT", "COUNT_DISTINCT", "MAX", "MIN", "SUM"]

CHART_DATA_ADHOC_METRIC_SCHEMA_AGGREGATE_VALUES: set[ChartDataAdhocMetricSchemaAggregate] = {
    "AVG",
    "COUNT",
    "COUNT_DISTINCT",
    "MAX",
    "MIN",
    "SUM",
}


def check_chart_data_adhoc_metric_schema_aggregate(value: str) -> ChartDataAdhocMetricSchemaAggregate:
    if value in CHART_DATA_ADHOC_METRIC_SCHEMA_AGGREGATE_VALUES:
        return cast(ChartDataAdhocMetricSchemaAggregate, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_ADHOC_METRIC_SCHEMA_AGGREGATE_VALUES!r}")

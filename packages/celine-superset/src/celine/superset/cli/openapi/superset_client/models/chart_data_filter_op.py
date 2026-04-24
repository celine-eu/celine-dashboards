from typing import Literal, cast

ChartDataFilterOp = Literal[
    "!=",
    "<",
    "<=",
    "==",
    ">",
    ">=",
    "ILIKE",
    "IN",
    "IS FALSE",
    "IS NOT NULL",
    "IS NULL",
    "IS TRUE",
    "LIKE",
    "NOT IN",
    "NOT LIKE",
    "TEMPORAL_RANGE",
]

CHART_DATA_FILTER_OP_VALUES: set[ChartDataFilterOp] = {
    "!=",
    "<",
    "<=",
    "==",
    ">",
    ">=",
    "ILIKE",
    "IN",
    "IS FALSE",
    "IS NOT NULL",
    "IS NULL",
    "IS TRUE",
    "LIKE",
    "NOT IN",
    "NOT LIKE",
    "TEMPORAL_RANGE",
}


def check_chart_data_filter_op(value: str) -> ChartDataFilterOp:
    if value in CHART_DATA_FILTER_OP_VALUES:
        return cast(ChartDataFilterOp, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_FILTER_OP_VALUES!r}")

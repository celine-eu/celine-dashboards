from typing import Literal, cast

ChartDataResponseResultStatus = Literal["failed", "pending", "running", "scheduled", "stopped", "success", "timed_out"]

CHART_DATA_RESPONSE_RESULT_STATUS_VALUES: set[ChartDataResponseResultStatus] = {
    "failed",
    "pending",
    "running",
    "scheduled",
    "stopped",
    "success",
    "timed_out",
}


def check_chart_data_response_result_status(value: str) -> ChartDataResponseResultStatus:
    if value in CHART_DATA_RESPONSE_RESULT_STATUS_VALUES:
        return cast(ChartDataResponseResultStatus, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {CHART_DATA_RESPONSE_RESULT_STATUS_VALUES!r}")

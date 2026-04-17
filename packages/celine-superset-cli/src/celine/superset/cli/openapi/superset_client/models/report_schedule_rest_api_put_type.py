from typing import Literal, cast

ReportScheduleRestApiPutType = Literal["Alert", "Report"]

REPORT_SCHEDULE_REST_API_PUT_TYPE_VALUES: set[ReportScheduleRestApiPutType] = {
    "Alert",
    "Report",
}


def check_report_schedule_rest_api_put_type(value: str) -> ReportScheduleRestApiPutType:
    if value in REPORT_SCHEDULE_REST_API_PUT_TYPE_VALUES:
        return cast(ReportScheduleRestApiPutType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_PUT_TYPE_VALUES!r}")

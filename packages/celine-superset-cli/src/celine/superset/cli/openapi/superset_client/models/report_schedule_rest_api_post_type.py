from typing import Literal, cast

ReportScheduleRestApiPostType = Literal["Alert", "Report"]

REPORT_SCHEDULE_REST_API_POST_TYPE_VALUES: set[ReportScheduleRestApiPostType] = {
    "Alert",
    "Report",
}


def check_report_schedule_rest_api_post_type(value: str) -> ReportScheduleRestApiPostType:
    if value in REPORT_SCHEDULE_REST_API_POST_TYPE_VALUES:
        return cast(ReportScheduleRestApiPostType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_POST_TYPE_VALUES!r}")

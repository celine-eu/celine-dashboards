from typing import Literal, cast

ReportScheduleRestApiPostCreationMethod = Literal["alerts_reports", "charts", "dashboards"]

REPORT_SCHEDULE_REST_API_POST_CREATION_METHOD_VALUES: set[ReportScheduleRestApiPostCreationMethod] = {
    "alerts_reports",
    "charts",
    "dashboards",
}


def check_report_schedule_rest_api_post_creation_method(value: str) -> ReportScheduleRestApiPostCreationMethod:
    if value in REPORT_SCHEDULE_REST_API_POST_CREATION_METHOD_VALUES:
        return cast(ReportScheduleRestApiPostCreationMethod, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_POST_CREATION_METHOD_VALUES!r}"
    )

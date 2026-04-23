from typing import Literal, cast

ReportScheduleRestApiPostReportFormat = Literal["CSV", "PDF", "PNG", "TEXT"]

REPORT_SCHEDULE_REST_API_POST_REPORT_FORMAT_VALUES: set[ReportScheduleRestApiPostReportFormat] = {
    "CSV",
    "PDF",
    "PNG",
    "TEXT",
}


def check_report_schedule_rest_api_post_report_format(value: str) -> ReportScheduleRestApiPostReportFormat:
    if value in REPORT_SCHEDULE_REST_API_POST_REPORT_FORMAT_VALUES:
        return cast(ReportScheduleRestApiPostReportFormat, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_POST_REPORT_FORMAT_VALUES!r}"
    )

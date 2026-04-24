from typing import Literal, cast

ReportScheduleRestApiPutReportFormat = Literal["CSV", "PDF", "PNG", "TEXT"]

REPORT_SCHEDULE_REST_API_PUT_REPORT_FORMAT_VALUES: set[ReportScheduleRestApiPutReportFormat] = {
    "CSV",
    "PDF",
    "PNG",
    "TEXT",
}


def check_report_schedule_rest_api_put_report_format(value: str) -> ReportScheduleRestApiPutReportFormat:
    if value in REPORT_SCHEDULE_REST_API_PUT_REPORT_FORMAT_VALUES:
        return cast(ReportScheduleRestApiPutReportFormat, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_PUT_REPORT_FORMAT_VALUES!r}"
    )

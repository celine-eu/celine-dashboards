from typing import Literal, cast

ReportScheduleRestApiPutCreationMethodType1 = Literal["alerts_reports", "charts", "dashboards"]

REPORT_SCHEDULE_REST_API_PUT_CREATION_METHOD_TYPE_1_VALUES: set[ReportScheduleRestApiPutCreationMethodType1] = {
    "alerts_reports",
    "charts",
    "dashboards",
}


def check_report_schedule_rest_api_put_creation_method_type_1(
    value: str,
) -> ReportScheduleRestApiPutCreationMethodType1:
    if value in REPORT_SCHEDULE_REST_API_PUT_CREATION_METHOD_TYPE_1_VALUES:
        return cast(ReportScheduleRestApiPutCreationMethodType1, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_PUT_CREATION_METHOD_TYPE_1_VALUES!r}"
    )

from typing import Literal, cast

ReportScheduleRestApiPostValidatorType = Literal["not null", "operator"]

REPORT_SCHEDULE_REST_API_POST_VALIDATOR_TYPE_VALUES: set[ReportScheduleRestApiPostValidatorType] = {
    "not null",
    "operator",
}


def check_report_schedule_rest_api_post_validator_type(value: str) -> ReportScheduleRestApiPostValidatorType:
    if value in REPORT_SCHEDULE_REST_API_POST_VALIDATOR_TYPE_VALUES:
        return cast(ReportScheduleRestApiPostValidatorType, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_POST_VALIDATOR_TYPE_VALUES!r}"
    )

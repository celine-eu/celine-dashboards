from typing import Literal, cast

ReportScheduleRestApiPutValidatorTypeType3Type1 = Literal["not null", "operator"]

REPORT_SCHEDULE_REST_API_PUT_VALIDATOR_TYPE_TYPE_3_TYPE_1_VALUES: set[
    ReportScheduleRestApiPutValidatorTypeType3Type1
] = {
    "not null",
    "operator",
}


def check_report_schedule_rest_api_put_validator_type_type_3_type_1(
    value: str,
) -> ReportScheduleRestApiPutValidatorTypeType3Type1:
    if value in REPORT_SCHEDULE_REST_API_PUT_VALIDATOR_TYPE_TYPE_3_TYPE_1_VALUES:
        return cast(ReportScheduleRestApiPutValidatorTypeType3Type1, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {REPORT_SCHEDULE_REST_API_PUT_VALIDATOR_TYPE_TYPE_3_TYPE_1_VALUES!r}"
    )

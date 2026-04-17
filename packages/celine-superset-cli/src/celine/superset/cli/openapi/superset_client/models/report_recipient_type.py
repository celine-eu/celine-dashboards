from typing import Literal, cast

ReportRecipientType = Literal["Email", "Slack", "SlackV2"]

REPORT_RECIPIENT_TYPE_VALUES: set[ReportRecipientType] = {
    "Email",
    "Slack",
    "SlackV2",
}


def check_report_recipient_type(value: str) -> ReportRecipientType:
    if value in REPORT_RECIPIENT_TYPE_VALUES:
        return cast(ReportRecipientType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {REPORT_RECIPIENT_TYPE_VALUES!r}")

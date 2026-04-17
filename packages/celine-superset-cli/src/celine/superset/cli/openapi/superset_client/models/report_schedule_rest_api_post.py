from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.report_schedule_rest_api_post_creation_method import (
    ReportScheduleRestApiPostCreationMethod,
    check_report_schedule_rest_api_post_creation_method,
)
from ..models.report_schedule_rest_api_post_report_format import (
    ReportScheduleRestApiPostReportFormat,
    check_report_schedule_rest_api_post_report_format,
)
from ..models.report_schedule_rest_api_post_timezone import (
    ReportScheduleRestApiPostTimezone,
    check_report_schedule_rest_api_post_timezone,
)
from ..models.report_schedule_rest_api_post_type import (
    ReportScheduleRestApiPostType,
    check_report_schedule_rest_api_post_type,
)
from ..models.report_schedule_rest_api_post_validator_type import (
    ReportScheduleRestApiPostValidatorType,
    check_report_schedule_rest_api_post_validator_type,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.report_recipient import ReportRecipient
    from ..models.report_schedule_rest_api_post_extra import ReportScheduleRestApiPostExtra
    from ..models.validator_config_json import ValidatorConfigJSON


T = TypeVar("T", bound="ReportScheduleRestApiPost")


@_attrs_define
class ReportScheduleRestApiPost:
    """
    Attributes:
        crontab (str): A CRON expression.[Crontab Guru](https://crontab.guru/) is a helpful resource that can help you
            craft a CRON expression. Example: */5 * * * *.
        name (str): The report schedule name. Example: Daily dashboard email.
        type_ (ReportScheduleRestApiPostType): The report schedule type
        active (bool | Unset):
        chart (int | None | Unset):
        context_markdown (None | str | Unset): Markdown description
        creation_method (ReportScheduleRestApiPostCreationMethod | Unset): Creation method is used to inform the
            frontend whether the report/alert was created in the dashboard, chart, or alerts and reports UI.
        custom_width (int | None | Unset): Custom width of the screenshot in pixels Example: 1000.
        dashboard (int | None | Unset):
        database (int | Unset):
        description (None | str | Unset): Use a nice description to give context to this Alert/Report Example: Daily
            sales dashboard to marketing.
        email_subject (None | str | Unset): The report schedule subject line Example: [Report]  Report name: Dashboard
            or chart name.
        extra (ReportScheduleRestApiPostExtra | Unset):
        force_screenshot (bool | Unset):
        grace_period (int | Unset): Once an alert is triggered, how long, in seconds, before Superset nags you again.
            (in seconds) Example: 14400.
        log_retention (int | Unset): How long to keep the logs around for this report (in days) Example: 90.
        owners (list[int] | Unset):
        recipients (list[ReportRecipient] | Unset):
        report_format (ReportScheduleRestApiPostReportFormat | Unset):
        selected_tabs (list[int] | None | Unset):
        sql (str | Unset): A SQL statement that defines whether the alert should get triggered or not. The query is
            expected to return either NULL or a number value. Example: SELECT value FROM time_series_table.
        timezone (ReportScheduleRestApiPostTimezone | Unset): A timezone string that represents the location of the
            timezone.
        validator_config_json (ValidatorConfigJSON | Unset):
        validator_type (ReportScheduleRestApiPostValidatorType | Unset): Determines when to trigger alert based off
            value from alert query. Alerts will be triggered with these validator types:
            - Not Null - When the return value is Not NULL, Empty, or 0
            - Operator - When `sql_return_value comparison_operator threshold` is True e.g. `50 <= 75`<br>Supports the
            comparison operators <, <=, >, >=, ==, and !=
        working_timeout (int | Unset): If an alert is staled at a working state, how long until it's state is reset to
            error Example: 3600.
    """

    crontab: str
    name: str
    type_: ReportScheduleRestApiPostType
    active: bool | Unset = UNSET
    chart: int | None | Unset = UNSET
    context_markdown: None | str | Unset = UNSET
    creation_method: ReportScheduleRestApiPostCreationMethod | Unset = UNSET
    custom_width: int | None | Unset = UNSET
    dashboard: int | None | Unset = UNSET
    database: int | Unset = UNSET
    description: None | str | Unset = UNSET
    email_subject: None | str | Unset = UNSET
    extra: ReportScheduleRestApiPostExtra | Unset = UNSET
    force_screenshot: bool | Unset = UNSET
    grace_period: int | Unset = UNSET
    log_retention: int | Unset = UNSET
    owners: list[int] | Unset = UNSET
    recipients: list[ReportRecipient] | Unset = UNSET
    report_format: ReportScheduleRestApiPostReportFormat | Unset = UNSET
    selected_tabs: list[int] | None | Unset = UNSET
    sql: str | Unset = UNSET
    timezone: ReportScheduleRestApiPostTimezone | Unset = UNSET
    validator_config_json: ValidatorConfigJSON | Unset = UNSET
    validator_type: ReportScheduleRestApiPostValidatorType | Unset = UNSET
    working_timeout: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        crontab = self.crontab

        name = self.name

        type_: str = self.type_

        active = self.active

        chart: int | None | Unset
        if isinstance(self.chart, Unset):
            chart = UNSET
        else:
            chart = self.chart

        context_markdown: None | str | Unset
        if isinstance(self.context_markdown, Unset):
            context_markdown = UNSET
        else:
            context_markdown = self.context_markdown

        creation_method: str | Unset = UNSET
        if not isinstance(self.creation_method, Unset):
            creation_method = self.creation_method

        custom_width: int | None | Unset
        if isinstance(self.custom_width, Unset):
            custom_width = UNSET
        else:
            custom_width = self.custom_width

        dashboard: int | None | Unset
        if isinstance(self.dashboard, Unset):
            dashboard = UNSET
        else:
            dashboard = self.dashboard

        database = self.database

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        email_subject: None | str | Unset
        if isinstance(self.email_subject, Unset):
            email_subject = UNSET
        else:
            email_subject = self.email_subject

        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        force_screenshot = self.force_screenshot

        grace_period = self.grace_period

        log_retention = self.log_retention

        owners: list[int] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners

        recipients: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.recipients, Unset):
            recipients = []
            for recipients_item_data in self.recipients:
                recipients_item = recipients_item_data.to_dict()
                recipients.append(recipients_item)

        report_format: str | Unset = UNSET
        if not isinstance(self.report_format, Unset):
            report_format = self.report_format

        selected_tabs: list[int] | None | Unset
        if isinstance(self.selected_tabs, Unset):
            selected_tabs = UNSET
        elif isinstance(self.selected_tabs, list):
            selected_tabs = self.selected_tabs

        else:
            selected_tabs = self.selected_tabs

        sql = self.sql

        timezone: str | Unset = UNSET
        if not isinstance(self.timezone, Unset):
            timezone = self.timezone

        validator_config_json: dict[str, Any] | Unset = UNSET
        if not isinstance(self.validator_config_json, Unset):
            validator_config_json = self.validator_config_json.to_dict()

        validator_type: str | Unset = UNSET
        if not isinstance(self.validator_type, Unset):
            validator_type = self.validator_type

        working_timeout = self.working_timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "crontab": crontab,
                "name": name,
                "type": type_,
            }
        )
        if active is not UNSET:
            field_dict["active"] = active
        if chart is not UNSET:
            field_dict["chart"] = chart
        if context_markdown is not UNSET:
            field_dict["context_markdown"] = context_markdown
        if creation_method is not UNSET:
            field_dict["creation_method"] = creation_method
        if custom_width is not UNSET:
            field_dict["custom_width"] = custom_width
        if dashboard is not UNSET:
            field_dict["dashboard"] = dashboard
        if database is not UNSET:
            field_dict["database"] = database
        if description is not UNSET:
            field_dict["description"] = description
        if email_subject is not UNSET:
            field_dict["email_subject"] = email_subject
        if extra is not UNSET:
            field_dict["extra"] = extra
        if force_screenshot is not UNSET:
            field_dict["force_screenshot"] = force_screenshot
        if grace_period is not UNSET:
            field_dict["grace_period"] = grace_period
        if log_retention is not UNSET:
            field_dict["log_retention"] = log_retention
        if owners is not UNSET:
            field_dict["owners"] = owners
        if recipients is not UNSET:
            field_dict["recipients"] = recipients
        if report_format is not UNSET:
            field_dict["report_format"] = report_format
        if selected_tabs is not UNSET:
            field_dict["selected_tabs"] = selected_tabs
        if sql is not UNSET:
            field_dict["sql"] = sql
        if timezone is not UNSET:
            field_dict["timezone"] = timezone
        if validator_config_json is not UNSET:
            field_dict["validator_config_json"] = validator_config_json
        if validator_type is not UNSET:
            field_dict["validator_type"] = validator_type
        if working_timeout is not UNSET:
            field_dict["working_timeout"] = working_timeout

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.report_recipient import ReportRecipient
        from ..models.report_schedule_rest_api_post_extra import ReportScheduleRestApiPostExtra
        from ..models.validator_config_json import ValidatorConfigJSON

        d = dict(src_dict)
        crontab = d.pop("crontab")

        name = d.pop("name")

        type_ = check_report_schedule_rest_api_post_type(d.pop("type"))

        active = d.pop("active", UNSET)

        def _parse_chart(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        chart = _parse_chart(d.pop("chart", UNSET))

        def _parse_context_markdown(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        context_markdown = _parse_context_markdown(d.pop("context_markdown", UNSET))

        _creation_method = d.pop("creation_method", UNSET)
        creation_method: ReportScheduleRestApiPostCreationMethod | Unset
        if isinstance(_creation_method, Unset):
            creation_method = UNSET
        else:
            creation_method = check_report_schedule_rest_api_post_creation_method(_creation_method)

        def _parse_custom_width(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        custom_width = _parse_custom_width(d.pop("custom_width", UNSET))

        def _parse_dashboard(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        dashboard = _parse_dashboard(d.pop("dashboard", UNSET))

        database = d.pop("database", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_email_subject(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        email_subject = _parse_email_subject(d.pop("email_subject", UNSET))

        _extra = d.pop("extra", UNSET)
        extra: ReportScheduleRestApiPostExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = ReportScheduleRestApiPostExtra.from_dict(_extra)

        force_screenshot = d.pop("force_screenshot", UNSET)

        grace_period = d.pop("grace_period", UNSET)

        log_retention = d.pop("log_retention", UNSET)

        owners = cast(list[int], d.pop("owners", UNSET))

        _recipients = d.pop("recipients", UNSET)
        recipients: list[ReportRecipient] | Unset = UNSET
        if _recipients is not UNSET:
            recipients = []
            for recipients_item_data in _recipients:
                recipients_item = ReportRecipient.from_dict(recipients_item_data)

                recipients.append(recipients_item)

        _report_format = d.pop("report_format", UNSET)
        report_format: ReportScheduleRestApiPostReportFormat | Unset
        if isinstance(_report_format, Unset):
            report_format = UNSET
        else:
            report_format = check_report_schedule_rest_api_post_report_format(_report_format)

        def _parse_selected_tabs(data: object) -> list[int] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                selected_tabs_type_0 = cast(list[int], data)

                return selected_tabs_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[int] | None | Unset, data)

        selected_tabs = _parse_selected_tabs(d.pop("selected_tabs", UNSET))

        sql = d.pop("sql", UNSET)

        _timezone = d.pop("timezone", UNSET)
        timezone: ReportScheduleRestApiPostTimezone | Unset
        if isinstance(_timezone, Unset):
            timezone = UNSET
        else:
            timezone = check_report_schedule_rest_api_post_timezone(_timezone)

        _validator_config_json = d.pop("validator_config_json", UNSET)
        validator_config_json: ValidatorConfigJSON | Unset
        if isinstance(_validator_config_json, Unset):
            validator_config_json = UNSET
        else:
            validator_config_json = ValidatorConfigJSON.from_dict(_validator_config_json)

        _validator_type = d.pop("validator_type", UNSET)
        validator_type: ReportScheduleRestApiPostValidatorType | Unset
        if isinstance(_validator_type, Unset):
            validator_type = UNSET
        else:
            validator_type = check_report_schedule_rest_api_post_validator_type(_validator_type)

        working_timeout = d.pop("working_timeout", UNSET)

        report_schedule_rest_api_post = cls(
            crontab=crontab,
            name=name,
            type_=type_,
            active=active,
            chart=chart,
            context_markdown=context_markdown,
            creation_method=creation_method,
            custom_width=custom_width,
            dashboard=dashboard,
            database=database,
            description=description,
            email_subject=email_subject,
            extra=extra,
            force_screenshot=force_screenshot,
            grace_period=grace_period,
            log_retention=log_retention,
            owners=owners,
            recipients=recipients,
            report_format=report_format,
            selected_tabs=selected_tabs,
            sql=sql,
            timezone=timezone,
            validator_config_json=validator_config_json,
            validator_type=validator_type,
            working_timeout=working_timeout,
        )

        report_schedule_rest_api_post.additional_properties = d
        return report_schedule_rest_api_post

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

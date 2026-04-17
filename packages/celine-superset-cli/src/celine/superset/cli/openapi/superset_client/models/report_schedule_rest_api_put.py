from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.report_schedule_rest_api_put_creation_method_type_1 import (
    ReportScheduleRestApiPutCreationMethodType1,
    check_report_schedule_rest_api_put_creation_method_type_1,
)
from ..models.report_schedule_rest_api_put_report_format import (
    ReportScheduleRestApiPutReportFormat,
    check_report_schedule_rest_api_put_report_format,
)
from ..models.report_schedule_rest_api_put_timezone import (
    ReportScheduleRestApiPutTimezone,
    check_report_schedule_rest_api_put_timezone,
)
from ..models.report_schedule_rest_api_put_type import (
    ReportScheduleRestApiPutType,
    check_report_schedule_rest_api_put_type,
)
from ..models.report_schedule_rest_api_put_validator_type_type_1 import (
    ReportScheduleRestApiPutValidatorTypeType1,
    check_report_schedule_rest_api_put_validator_type_type_1,
)
from ..models.report_schedule_rest_api_put_validator_type_type_2_type_1 import (
    ReportScheduleRestApiPutValidatorTypeType2Type1,
    check_report_schedule_rest_api_put_validator_type_type_2_type_1,
)
from ..models.report_schedule_rest_api_put_validator_type_type_3_type_1 import (
    ReportScheduleRestApiPutValidatorTypeType3Type1,
    check_report_schedule_rest_api_put_validator_type_type_3_type_1,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.report_recipient import ReportRecipient
    from ..models.report_schedule_rest_api_put_extra import ReportScheduleRestApiPutExtra
    from ..models.validator_config_json import ValidatorConfigJSON


T = TypeVar("T", bound="ReportScheduleRestApiPut")


@_attrs_define
class ReportScheduleRestApiPut:
    """
    Attributes:
        active (bool | Unset):
        chart (int | None | Unset):
        context_markdown (None | str | Unset): Markdown description
        creation_method (None | ReportScheduleRestApiPutCreationMethodType1 | Unset): Creation method is used to inform
            the frontend whether the report/alert was created in the dashboard, chart, or alerts and reports UI.
        crontab (str | Unset): A CRON expression.[Crontab Guru](https://crontab.guru/) is a helpful resource that can
            help you craft a CRON expression.
        custom_width (int | None | Unset): Custom width of the screenshot in pixels Example: 1000.
        dashboard (int | None | Unset):
        database (int | Unset):
        description (None | str | Unset): Use a nice description to give context to this Alert/Report Example: Daily
            sales dashboard to marketing.
        email_subject (None | str | Unset): The report schedule subject line Example: [Report]  Report name: Dashboard
            or chart name.
        extra (ReportScheduleRestApiPutExtra | Unset):
        force_screenshot (bool | Unset):
        grace_period (int | Unset): Once an alert is triggered, how long, in seconds, before Superset nags you again.
            (in seconds) Example: 14400.
        log_retention (int | Unset): How long to keep the logs around for this report (in days) Example: 90.
        name (str | Unset): The report schedule name.
        owners (list[int] | Unset):
        recipients (list[ReportRecipient] | Unset):
        report_format (ReportScheduleRestApiPutReportFormat | Unset):
        sql (None | str | Unset): A SQL statement that defines whether the alert should get triggered or not. The query
            is expected to return either NULL or a number value. Example: SELECT value FROM time_series_table.
        timezone (ReportScheduleRestApiPutTimezone | Unset): A timezone string that represents the location of the
            timezone.
        type_ (ReportScheduleRestApiPutType | Unset): The report schedule type
        validator_config_json (ValidatorConfigJSON | Unset):
        validator_type (None | ReportScheduleRestApiPutValidatorTypeType1 |
            ReportScheduleRestApiPutValidatorTypeType2Type1 | ReportScheduleRestApiPutValidatorTypeType3Type1 | Unset):
            Determines when to trigger alert based off value from alert query. Alerts will be triggered with these validator
            types:
            - Not Null - When the return value is Not NULL, Empty, or 0
            - Operator - When `sql_return_value comparison_operator threshold` is True e.g. `50 <= 75`<br>Supports the
            comparison operators <, <=, >, >=, ==, and !=
        working_timeout (int | None | Unset): If an alert is staled at a working state, how long until it's state is
            reset to error Example: 3600.
    """

    active: bool | Unset = UNSET
    chart: int | None | Unset = UNSET
    context_markdown: None | str | Unset = UNSET
    creation_method: None | ReportScheduleRestApiPutCreationMethodType1 | Unset = UNSET
    crontab: str | Unset = UNSET
    custom_width: int | None | Unset = UNSET
    dashboard: int | None | Unset = UNSET
    database: int | Unset = UNSET
    description: None | str | Unset = UNSET
    email_subject: None | str | Unset = UNSET
    extra: ReportScheduleRestApiPutExtra | Unset = UNSET
    force_screenshot: bool | Unset = UNSET
    grace_period: int | Unset = UNSET
    log_retention: int | Unset = UNSET
    name: str | Unset = UNSET
    owners: list[int] | Unset = UNSET
    recipients: list[ReportRecipient] | Unset = UNSET
    report_format: ReportScheduleRestApiPutReportFormat | Unset = UNSET
    sql: None | str | Unset = UNSET
    timezone: ReportScheduleRestApiPutTimezone | Unset = UNSET
    type_: ReportScheduleRestApiPutType | Unset = UNSET
    validator_config_json: ValidatorConfigJSON | Unset = UNSET
    validator_type: (
        None
        | ReportScheduleRestApiPutValidatorTypeType1
        | ReportScheduleRestApiPutValidatorTypeType2Type1
        | ReportScheduleRestApiPutValidatorTypeType3Type1
        | Unset
    ) = UNSET
    working_timeout: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
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

        creation_method: None | str | Unset
        if isinstance(self.creation_method, Unset):
            creation_method = UNSET
        elif isinstance(self.creation_method, str):
            creation_method = self.creation_method
        else:
            creation_method = self.creation_method

        crontab = self.crontab

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

        name = self.name

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

        sql: None | str | Unset
        if isinstance(self.sql, Unset):
            sql = UNSET
        else:
            sql = self.sql

        timezone: str | Unset = UNSET
        if not isinstance(self.timezone, Unset):
            timezone = self.timezone

        type_: str | Unset = UNSET
        if not isinstance(self.type_, Unset):
            type_ = self.type_

        validator_config_json: dict[str, Any] | Unset = UNSET
        if not isinstance(self.validator_config_json, Unset):
            validator_config_json = self.validator_config_json.to_dict()

        validator_type: None | str | Unset
        if isinstance(self.validator_type, Unset):
            validator_type = UNSET
        elif isinstance(self.validator_type, str):
            validator_type = self.validator_type
        elif isinstance(self.validator_type, str):
            validator_type = self.validator_type
        elif isinstance(self.validator_type, str):
            validator_type = self.validator_type
        else:
            validator_type = self.validator_type

        working_timeout: int | None | Unset
        if isinstance(self.working_timeout, Unset):
            working_timeout = UNSET
        else:
            working_timeout = self.working_timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if active is not UNSET:
            field_dict["active"] = active
        if chart is not UNSET:
            field_dict["chart"] = chart
        if context_markdown is not UNSET:
            field_dict["context_markdown"] = context_markdown
        if creation_method is not UNSET:
            field_dict["creation_method"] = creation_method
        if crontab is not UNSET:
            field_dict["crontab"] = crontab
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
        if name is not UNSET:
            field_dict["name"] = name
        if owners is not UNSET:
            field_dict["owners"] = owners
        if recipients is not UNSET:
            field_dict["recipients"] = recipients
        if report_format is not UNSET:
            field_dict["report_format"] = report_format
        if sql is not UNSET:
            field_dict["sql"] = sql
        if timezone is not UNSET:
            field_dict["timezone"] = timezone
        if type_ is not UNSET:
            field_dict["type"] = type_
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
        from ..models.report_schedule_rest_api_put_extra import ReportScheduleRestApiPutExtra
        from ..models.validator_config_json import ValidatorConfigJSON

        d = dict(src_dict)
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

        def _parse_creation_method(data: object) -> None | ReportScheduleRestApiPutCreationMethodType1 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                creation_method_type_1 = check_report_schedule_rest_api_put_creation_method_type_1(data)

                return creation_method_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ReportScheduleRestApiPutCreationMethodType1 | Unset, data)

        creation_method = _parse_creation_method(d.pop("creation_method", UNSET))

        crontab = d.pop("crontab", UNSET)

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
        extra: ReportScheduleRestApiPutExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = ReportScheduleRestApiPutExtra.from_dict(_extra)

        force_screenshot = d.pop("force_screenshot", UNSET)

        grace_period = d.pop("grace_period", UNSET)

        log_retention = d.pop("log_retention", UNSET)

        name = d.pop("name", UNSET)

        owners = cast(list[int], d.pop("owners", UNSET))

        _recipients = d.pop("recipients", UNSET)
        recipients: list[ReportRecipient] | Unset = UNSET
        if _recipients is not UNSET:
            recipients = []
            for recipients_item_data in _recipients:
                recipients_item = ReportRecipient.from_dict(recipients_item_data)

                recipients.append(recipients_item)

        _report_format = d.pop("report_format", UNSET)
        report_format: ReportScheduleRestApiPutReportFormat | Unset
        if isinstance(_report_format, Unset):
            report_format = UNSET
        else:
            report_format = check_report_schedule_rest_api_put_report_format(_report_format)

        def _parse_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql = _parse_sql(d.pop("sql", UNSET))

        _timezone = d.pop("timezone", UNSET)
        timezone: ReportScheduleRestApiPutTimezone | Unset
        if isinstance(_timezone, Unset):
            timezone = UNSET
        else:
            timezone = check_report_schedule_rest_api_put_timezone(_timezone)

        _type_ = d.pop("type", UNSET)
        type_: ReportScheduleRestApiPutType | Unset
        if isinstance(_type_, Unset):
            type_ = UNSET
        else:
            type_ = check_report_schedule_rest_api_put_type(_type_)

        _validator_config_json = d.pop("validator_config_json", UNSET)
        validator_config_json: ValidatorConfigJSON | Unset
        if isinstance(_validator_config_json, Unset):
            validator_config_json = UNSET
        else:
            validator_config_json = ValidatorConfigJSON.from_dict(_validator_config_json)

        def _parse_validator_type(
            data: object,
        ) -> (
            None
            | ReportScheduleRestApiPutValidatorTypeType1
            | ReportScheduleRestApiPutValidatorTypeType2Type1
            | ReportScheduleRestApiPutValidatorTypeType3Type1
            | Unset
        ):
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                validator_type_type_1 = check_report_schedule_rest_api_put_validator_type_type_1(data)

                return validator_type_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, str):
                    raise TypeError()
                validator_type_type_2_type_1 = check_report_schedule_rest_api_put_validator_type_type_2_type_1(data)

                return validator_type_type_2_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, str):
                    raise TypeError()
                validator_type_type_3_type_1 = check_report_schedule_rest_api_put_validator_type_type_3_type_1(data)

                return validator_type_type_3_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(
                None
                | ReportScheduleRestApiPutValidatorTypeType1
                | ReportScheduleRestApiPutValidatorTypeType2Type1
                | ReportScheduleRestApiPutValidatorTypeType3Type1
                | Unset,
                data,
            )

        validator_type = _parse_validator_type(d.pop("validator_type", UNSET))

        def _parse_working_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        working_timeout = _parse_working_timeout(d.pop("working_timeout", UNSET))

        report_schedule_rest_api_put = cls(
            active=active,
            chart=chart,
            context_markdown=context_markdown,
            creation_method=creation_method,
            crontab=crontab,
            custom_width=custom_width,
            dashboard=dashboard,
            database=database,
            description=description,
            email_subject=email_subject,
            extra=extra,
            force_screenshot=force_screenshot,
            grace_period=grace_period,
            log_retention=log_retention,
            name=name,
            owners=owners,
            recipients=recipients,
            report_format=report_format,
            sql=sql,
            timezone=timezone,
            type_=type_,
            validator_config_json=validator_config_json,
            validator_type=validator_type,
            working_timeout=working_timeout,
        )

        report_schedule_rest_api_put.additional_properties = d
        return report_schedule_rest_api_put

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

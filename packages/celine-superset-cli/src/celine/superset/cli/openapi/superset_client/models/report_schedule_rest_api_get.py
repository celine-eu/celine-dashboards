from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.report_schedule_rest_api_get_dashboard import ReportScheduleRestApiGetDashboard
    from ..models.report_schedule_rest_api_get_database import ReportScheduleRestApiGetDatabase
    from ..models.report_schedule_rest_api_get_report_recipients import ReportScheduleRestApiGetReportRecipients
    from ..models.report_schedule_rest_api_get_slice import ReportScheduleRestApiGetSlice
    from ..models.report_schedule_rest_api_get_user import ReportScheduleRestApiGetUser


T = TypeVar("T", bound="ReportScheduleRestApiGet")


@_attrs_define
class ReportScheduleRestApiGet:
    """
    Attributes:
        crontab (str):
        name (str):
        recipients (ReportScheduleRestApiGetReportRecipients):
        type_ (str):
        active (bool | None | Unset):
        chart (ReportScheduleRestApiGetSlice | Unset):
        context_markdown (None | str | Unset):
        creation_method (None | str | Unset):
        custom_width (int | None | Unset):
        dashboard (ReportScheduleRestApiGetDashboard | Unset):
        database (ReportScheduleRestApiGetDatabase | Unset):
        description (None | str | Unset):
        email_subject (None | str | Unset):
        extra (Any | Unset):
        force_screenshot (bool | None | Unset):
        grace_period (int | None | Unset):
        id (int | Unset):
        last_eval_dttm (datetime.datetime | None | Unset):
        last_state (None | str | Unset):
        last_value (float | None | Unset):
        last_value_row_json (None | str | Unset):
        log_retention (int | None | Unset):
        owners (ReportScheduleRestApiGetUser | Unset):
        report_format (None | str | Unset):
        sql (None | str | Unset):
        timezone (str | Unset):
        validator_config_json (None | str | Unset):
        validator_type (None | str | Unset):
        working_timeout (int | None | Unset):
    """

    crontab: str
    name: str
    recipients: ReportScheduleRestApiGetReportRecipients
    type_: str
    active: bool | None | Unset = UNSET
    chart: ReportScheduleRestApiGetSlice | Unset = UNSET
    context_markdown: None | str | Unset = UNSET
    creation_method: None | str | Unset = UNSET
    custom_width: int | None | Unset = UNSET
    dashboard: ReportScheduleRestApiGetDashboard | Unset = UNSET
    database: ReportScheduleRestApiGetDatabase | Unset = UNSET
    description: None | str | Unset = UNSET
    email_subject: None | str | Unset = UNSET
    extra: Any | Unset = UNSET
    force_screenshot: bool | None | Unset = UNSET
    grace_period: int | None | Unset = UNSET
    id: int | Unset = UNSET
    last_eval_dttm: datetime.datetime | None | Unset = UNSET
    last_state: None | str | Unset = UNSET
    last_value: float | None | Unset = UNSET
    last_value_row_json: None | str | Unset = UNSET
    log_retention: int | None | Unset = UNSET
    owners: ReportScheduleRestApiGetUser | Unset = UNSET
    report_format: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    timezone: str | Unset = UNSET
    validator_config_json: None | str | Unset = UNSET
    validator_type: None | str | Unset = UNSET
    working_timeout: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        crontab = self.crontab

        name = self.name

        recipients = self.recipients.to_dict()

        type_ = self.type_

        active: bool | None | Unset
        if isinstance(self.active, Unset):
            active = UNSET
        else:
            active = self.active

        chart: dict[str, Any] | Unset = UNSET
        if not isinstance(self.chart, Unset):
            chart = self.chart.to_dict()

        context_markdown: None | str | Unset
        if isinstance(self.context_markdown, Unset):
            context_markdown = UNSET
        else:
            context_markdown = self.context_markdown

        creation_method: None | str | Unset
        if isinstance(self.creation_method, Unset):
            creation_method = UNSET
        else:
            creation_method = self.creation_method

        custom_width: int | None | Unset
        if isinstance(self.custom_width, Unset):
            custom_width = UNSET
        else:
            custom_width = self.custom_width

        dashboard: dict[str, Any] | Unset = UNSET
        if not isinstance(self.dashboard, Unset):
            dashboard = self.dashboard.to_dict()

        database: dict[str, Any] | Unset = UNSET
        if not isinstance(self.database, Unset):
            database = self.database.to_dict()

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

        extra = self.extra

        force_screenshot: bool | None | Unset
        if isinstance(self.force_screenshot, Unset):
            force_screenshot = UNSET
        else:
            force_screenshot = self.force_screenshot

        grace_period: int | None | Unset
        if isinstance(self.grace_period, Unset):
            grace_period = UNSET
        else:
            grace_period = self.grace_period

        id = self.id

        last_eval_dttm: None | str | Unset
        if isinstance(self.last_eval_dttm, Unset):
            last_eval_dttm = UNSET
        elif isinstance(self.last_eval_dttm, datetime.datetime):
            last_eval_dttm = self.last_eval_dttm.isoformat()
        else:
            last_eval_dttm = self.last_eval_dttm

        last_state: None | str | Unset
        if isinstance(self.last_state, Unset):
            last_state = UNSET
        else:
            last_state = self.last_state

        last_value: float | None | Unset
        if isinstance(self.last_value, Unset):
            last_value = UNSET
        else:
            last_value = self.last_value

        last_value_row_json: None | str | Unset
        if isinstance(self.last_value_row_json, Unset):
            last_value_row_json = UNSET
        else:
            last_value_row_json = self.last_value_row_json

        log_retention: int | None | Unset
        if isinstance(self.log_retention, Unset):
            log_retention = UNSET
        else:
            log_retention = self.log_retention

        owners: dict[str, Any] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners.to_dict()

        report_format: None | str | Unset
        if isinstance(self.report_format, Unset):
            report_format = UNSET
        else:
            report_format = self.report_format

        sql: None | str | Unset
        if isinstance(self.sql, Unset):
            sql = UNSET
        else:
            sql = self.sql

        timezone = self.timezone

        validator_config_json: None | str | Unset
        if isinstance(self.validator_config_json, Unset):
            validator_config_json = UNSET
        else:
            validator_config_json = self.validator_config_json

        validator_type: None | str | Unset
        if isinstance(self.validator_type, Unset):
            validator_type = UNSET
        else:
            validator_type = self.validator_type

        working_timeout: int | None | Unset
        if isinstance(self.working_timeout, Unset):
            working_timeout = UNSET
        else:
            working_timeout = self.working_timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "crontab": crontab,
                "name": name,
                "recipients": recipients,
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
        if id is not UNSET:
            field_dict["id"] = id
        if last_eval_dttm is not UNSET:
            field_dict["last_eval_dttm"] = last_eval_dttm
        if last_state is not UNSET:
            field_dict["last_state"] = last_state
        if last_value is not UNSET:
            field_dict["last_value"] = last_value
        if last_value_row_json is not UNSET:
            field_dict["last_value_row_json"] = last_value_row_json
        if log_retention is not UNSET:
            field_dict["log_retention"] = log_retention
        if owners is not UNSET:
            field_dict["owners"] = owners
        if report_format is not UNSET:
            field_dict["report_format"] = report_format
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
        from ..models.report_schedule_rest_api_get_dashboard import ReportScheduleRestApiGetDashboard
        from ..models.report_schedule_rest_api_get_database import ReportScheduleRestApiGetDatabase
        from ..models.report_schedule_rest_api_get_report_recipients import ReportScheduleRestApiGetReportRecipients
        from ..models.report_schedule_rest_api_get_slice import ReportScheduleRestApiGetSlice
        from ..models.report_schedule_rest_api_get_user import ReportScheduleRestApiGetUser

        d = dict(src_dict)
        crontab = d.pop("crontab")

        name = d.pop("name")

        recipients = ReportScheduleRestApiGetReportRecipients.from_dict(d.pop("recipients"))

        type_ = d.pop("type")

        def _parse_active(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        active = _parse_active(d.pop("active", UNSET))

        _chart = d.pop("chart", UNSET)
        chart: ReportScheduleRestApiGetSlice | Unset
        if isinstance(_chart, Unset):
            chart = UNSET
        else:
            chart = ReportScheduleRestApiGetSlice.from_dict(_chart)

        def _parse_context_markdown(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        context_markdown = _parse_context_markdown(d.pop("context_markdown", UNSET))

        def _parse_creation_method(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        creation_method = _parse_creation_method(d.pop("creation_method", UNSET))

        def _parse_custom_width(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        custom_width = _parse_custom_width(d.pop("custom_width", UNSET))

        _dashboard = d.pop("dashboard", UNSET)
        dashboard: ReportScheduleRestApiGetDashboard | Unset
        if isinstance(_dashboard, Unset):
            dashboard = UNSET
        else:
            dashboard = ReportScheduleRestApiGetDashboard.from_dict(_dashboard)

        _database = d.pop("database", UNSET)
        database: ReportScheduleRestApiGetDatabase | Unset
        if isinstance(_database, Unset):
            database = UNSET
        else:
            database = ReportScheduleRestApiGetDatabase.from_dict(_database)

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

        extra = d.pop("extra", UNSET)

        def _parse_force_screenshot(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        force_screenshot = _parse_force_screenshot(d.pop("force_screenshot", UNSET))

        def _parse_grace_period(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        grace_period = _parse_grace_period(d.pop("grace_period", UNSET))

        id = d.pop("id", UNSET)

        def _parse_last_eval_dttm(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_eval_dttm_type_0 = isoparse(data)

                return last_eval_dttm_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_eval_dttm = _parse_last_eval_dttm(d.pop("last_eval_dttm", UNSET))

        def _parse_last_state(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_state = _parse_last_state(d.pop("last_state", UNSET))

        def _parse_last_value(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        last_value = _parse_last_value(d.pop("last_value", UNSET))

        def _parse_last_value_row_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_value_row_json = _parse_last_value_row_json(d.pop("last_value_row_json", UNSET))

        def _parse_log_retention(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        log_retention = _parse_log_retention(d.pop("log_retention", UNSET))

        _owners = d.pop("owners", UNSET)
        owners: ReportScheduleRestApiGetUser | Unset
        if isinstance(_owners, Unset):
            owners = UNSET
        else:
            owners = ReportScheduleRestApiGetUser.from_dict(_owners)

        def _parse_report_format(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        report_format = _parse_report_format(d.pop("report_format", UNSET))

        def _parse_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql = _parse_sql(d.pop("sql", UNSET))

        timezone = d.pop("timezone", UNSET)

        def _parse_validator_config_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        validator_config_json = _parse_validator_config_json(d.pop("validator_config_json", UNSET))

        def _parse_validator_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        validator_type = _parse_validator_type(d.pop("validator_type", UNSET))

        def _parse_working_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        working_timeout = _parse_working_timeout(d.pop("working_timeout", UNSET))

        report_schedule_rest_api_get = cls(
            crontab=crontab,
            name=name,
            recipients=recipients,
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
            id=id,
            last_eval_dttm=last_eval_dttm,
            last_state=last_state,
            last_value=last_value,
            last_value_row_json=last_value_row_json,
            log_retention=log_retention,
            owners=owners,
            report_format=report_format,
            sql=sql,
            timezone=timezone,
            validator_config_json=validator_config_json,
            validator_type=validator_type,
            working_timeout=working_timeout,
        )

        report_schedule_rest_api_get.additional_properties = d
        return report_schedule_rest_api_get

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

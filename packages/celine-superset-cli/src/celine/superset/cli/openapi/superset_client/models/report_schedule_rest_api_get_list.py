from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.report_schedule_rest_api_get_list_report_recipients import (
        ReportScheduleRestApiGetListReportRecipients,
    )
    from ..models.report_schedule_rest_api_get_list_user import ReportScheduleRestApiGetListUser
    from ..models.report_schedule_rest_api_get_list_user_1 import ReportScheduleRestApiGetListUser1
    from ..models.report_schedule_rest_api_get_list_user_2 import ReportScheduleRestApiGetListUser2


T = TypeVar("T", bound="ReportScheduleRestApiGetList")


@_attrs_define
class ReportScheduleRestApiGetList:
    """
    Attributes:
        crontab (str):
        name (str):
        recipients (ReportScheduleRestApiGetListReportRecipients):
        type_ (str):
        active (bool | None | Unset):
        changed_by (ReportScheduleRestApiGetListUser | Unset):
        changed_on (datetime.datetime | None | Unset):
        changed_on_delta_humanized (Any | Unset):
        chart_id (Any | Unset):
        created_by (ReportScheduleRestApiGetListUser1 | Unset):
        created_on (datetime.datetime | None | Unset):
        creation_method (None | str | Unset):
        crontab_humanized (Any | Unset):
        dashboard_id (Any | Unset):
        description (None | str | Unset):
        extra (Any | Unset):
        id (int | Unset):
        last_eval_dttm (datetime.datetime | None | Unset):
        last_state (None | str | Unset):
        owners (ReportScheduleRestApiGetListUser2 | Unset):
        timezone (str | Unset):
    """

    crontab: str
    name: str
    recipients: ReportScheduleRestApiGetListReportRecipients
    type_: str
    active: bool | None | Unset = UNSET
    changed_by: ReportScheduleRestApiGetListUser | Unset = UNSET
    changed_on: datetime.datetime | None | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    chart_id: Any | Unset = UNSET
    created_by: ReportScheduleRestApiGetListUser1 | Unset = UNSET
    created_on: datetime.datetime | None | Unset = UNSET
    creation_method: None | str | Unset = UNSET
    crontab_humanized: Any | Unset = UNSET
    dashboard_id: Any | Unset = UNSET
    description: None | str | Unset = UNSET
    extra: Any | Unset = UNSET
    id: int | Unset = UNSET
    last_eval_dttm: datetime.datetime | None | Unset = UNSET
    last_state: None | str | Unset = UNSET
    owners: ReportScheduleRestApiGetListUser2 | Unset = UNSET
    timezone: str | Unset = UNSET
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

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        changed_on_delta_humanized = self.changed_on_delta_humanized

        chart_id = self.chart_id

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on: None | str | Unset
        if isinstance(self.created_on, Unset):
            created_on = UNSET
        elif isinstance(self.created_on, datetime.datetime):
            created_on = self.created_on.isoformat()
        else:
            created_on = self.created_on

        creation_method: None | str | Unset
        if isinstance(self.creation_method, Unset):
            creation_method = UNSET
        else:
            creation_method = self.creation_method

        crontab_humanized = self.crontab_humanized

        dashboard_id = self.dashboard_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        extra = self.extra

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

        owners: dict[str, Any] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners.to_dict()

        timezone = self.timezone

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
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if chart_id is not UNSET:
            field_dict["chart_id"] = chart_id
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on is not UNSET:
            field_dict["created_on"] = created_on
        if creation_method is not UNSET:
            field_dict["creation_method"] = creation_method
        if crontab_humanized is not UNSET:
            field_dict["crontab_humanized"] = crontab_humanized
        if dashboard_id is not UNSET:
            field_dict["dashboard_id"] = dashboard_id
        if description is not UNSET:
            field_dict["description"] = description
        if extra is not UNSET:
            field_dict["extra"] = extra
        if id is not UNSET:
            field_dict["id"] = id
        if last_eval_dttm is not UNSET:
            field_dict["last_eval_dttm"] = last_eval_dttm
        if last_state is not UNSET:
            field_dict["last_state"] = last_state
        if owners is not UNSET:
            field_dict["owners"] = owners
        if timezone is not UNSET:
            field_dict["timezone"] = timezone

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.report_schedule_rest_api_get_list_report_recipients import (
            ReportScheduleRestApiGetListReportRecipients,
        )
        from ..models.report_schedule_rest_api_get_list_user import ReportScheduleRestApiGetListUser
        from ..models.report_schedule_rest_api_get_list_user_1 import ReportScheduleRestApiGetListUser1
        from ..models.report_schedule_rest_api_get_list_user_2 import ReportScheduleRestApiGetListUser2

        d = dict(src_dict)
        crontab = d.pop("crontab")

        name = d.pop("name")

        recipients = ReportScheduleRestApiGetListReportRecipients.from_dict(d.pop("recipients"))

        type_ = d.pop("type")

        def _parse_active(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        active = _parse_active(d.pop("active", UNSET))

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: ReportScheduleRestApiGetListUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = ReportScheduleRestApiGetListUser.from_dict(_changed_by)

        def _parse_changed_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                changed_on_type_0 = isoparse(data)

                return changed_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        changed_on = _parse_changed_on(d.pop("changed_on", UNSET))

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        chart_id = d.pop("chart_id", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: ReportScheduleRestApiGetListUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = ReportScheduleRestApiGetListUser1.from_dict(_created_by)

        def _parse_created_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                created_on_type_0 = isoparse(data)

                return created_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        created_on = _parse_created_on(d.pop("created_on", UNSET))

        def _parse_creation_method(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        creation_method = _parse_creation_method(d.pop("creation_method", UNSET))

        crontab_humanized = d.pop("crontab_humanized", UNSET)

        dashboard_id = d.pop("dashboard_id", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        extra = d.pop("extra", UNSET)

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

        _owners = d.pop("owners", UNSET)
        owners: ReportScheduleRestApiGetListUser2 | Unset
        if isinstance(_owners, Unset):
            owners = UNSET
        else:
            owners = ReportScheduleRestApiGetListUser2.from_dict(_owners)

        timezone = d.pop("timezone", UNSET)

        report_schedule_rest_api_get_list = cls(
            crontab=crontab,
            name=name,
            recipients=recipients,
            type_=type_,
            active=active,
            changed_by=changed_by,
            changed_on=changed_on,
            changed_on_delta_humanized=changed_on_delta_humanized,
            chart_id=chart_id,
            created_by=created_by,
            created_on=created_on,
            creation_method=creation_method,
            crontab_humanized=crontab_humanized,
            dashboard_id=dashboard_id,
            description=description,
            extra=extra,
            id=id,
            last_eval_dttm=last_eval_dttm,
            last_state=last_state,
            owners=owners,
            timezone=timezone,
        )

        report_schedule_rest_api_get_list.additional_properties = d
        return report_schedule_rest_api_get_list

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

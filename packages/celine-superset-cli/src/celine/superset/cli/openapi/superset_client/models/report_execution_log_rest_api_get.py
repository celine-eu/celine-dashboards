from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportExecutionLogRestApiGet")


@_attrs_define
class ReportExecutionLogRestApiGet:
    """
    Attributes:
        scheduled_dttm (datetime.datetime):
        state (str):
        end_dttm (datetime.datetime | None | Unset):
        error_message (None | str | Unset):
        id (int | Unset):
        start_dttm (datetime.datetime | None | Unset):
        uuid (None | Unset | UUID):
        value (float | None | Unset):
        value_row_json (None | str | Unset):
    """

    scheduled_dttm: datetime.datetime
    state: str
    end_dttm: datetime.datetime | None | Unset = UNSET
    error_message: None | str | Unset = UNSET
    id: int | Unset = UNSET
    start_dttm: datetime.datetime | None | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    value: float | None | Unset = UNSET
    value_row_json: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scheduled_dttm = self.scheduled_dttm.isoformat()

        state = self.state

        end_dttm: None | str | Unset
        if isinstance(self.end_dttm, Unset):
            end_dttm = UNSET
        elif isinstance(self.end_dttm, datetime.datetime):
            end_dttm = self.end_dttm.isoformat()
        else:
            end_dttm = self.end_dttm

        error_message: None | str | Unset
        if isinstance(self.error_message, Unset):
            error_message = UNSET
        else:
            error_message = self.error_message

        id = self.id

        start_dttm: None | str | Unset
        if isinstance(self.start_dttm, Unset):
            start_dttm = UNSET
        elif isinstance(self.start_dttm, datetime.datetime):
            start_dttm = self.start_dttm.isoformat()
        else:
            start_dttm = self.start_dttm

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        value: float | None | Unset
        if isinstance(self.value, Unset):
            value = UNSET
        else:
            value = self.value

        value_row_json: None | str | Unset
        if isinstance(self.value_row_json, Unset):
            value_row_json = UNSET
        else:
            value_row_json = self.value_row_json

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scheduled_dttm": scheduled_dttm,
                "state": state,
            }
        )
        if end_dttm is not UNSET:
            field_dict["end_dttm"] = end_dttm
        if error_message is not UNSET:
            field_dict["error_message"] = error_message
        if id is not UNSET:
            field_dict["id"] = id
        if start_dttm is not UNSET:
            field_dict["start_dttm"] = start_dttm
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if value is not UNSET:
            field_dict["value"] = value
        if value_row_json is not UNSET:
            field_dict["value_row_json"] = value_row_json

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scheduled_dttm = isoparse(d.pop("scheduled_dttm"))

        state = d.pop("state")

        def _parse_end_dttm(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                end_dttm_type_0 = isoparse(data)

                return end_dttm_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        end_dttm = _parse_end_dttm(d.pop("end_dttm", UNSET))

        def _parse_error_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error_message = _parse_error_message(d.pop("error_message", UNSET))

        id = d.pop("id", UNSET)

        def _parse_start_dttm(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                start_dttm_type_0 = isoparse(data)

                return start_dttm_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        start_dttm = _parse_start_dttm(d.pop("start_dttm", UNSET))

        def _parse_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                uuid_type_0 = UUID(data)

                return uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        uuid = _parse_uuid(d.pop("uuid", UNSET))

        def _parse_value(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        value = _parse_value(d.pop("value", UNSET))

        def _parse_value_row_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        value_row_json = _parse_value_row_json(d.pop("value_row_json", UNSET))

        report_execution_log_rest_api_get = cls(
            scheduled_dttm=scheduled_dttm,
            state=state,
            end_dttm=end_dttm,
            error_message=error_message,
            id=id,
            start_dttm=start_dttm,
            uuid=uuid,
            value=value,
            value_row_json=value_row_json,
        )

        report_execution_log_rest_api_get.additional_properties = d
        return report_execution_log_rest_api_get

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

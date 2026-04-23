from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.log_rest_api_get_user import LogRestApiGetUser


T = TypeVar("T", bound="LogRestApiGet")


@_attrs_define
class LogRestApiGet:
    """
    Attributes:
        action (None | str | Unset):
        dashboard_id (int | None | Unset):
        dttm (datetime.datetime | None | Unset):
        duration_ms (int | None | Unset):
        json (None | str | Unset):
        referrer (None | str | Unset):
        slice_id (int | None | Unset):
        user (LogRestApiGetUser | Unset):
        user_id (Any | Unset):
    """

    action: None | str | Unset = UNSET
    dashboard_id: int | None | Unset = UNSET
    dttm: datetime.datetime | None | Unset = UNSET
    duration_ms: int | None | Unset = UNSET
    json: None | str | Unset = UNSET
    referrer: None | str | Unset = UNSET
    slice_id: int | None | Unset = UNSET
    user: LogRestApiGetUser | Unset = UNSET
    user_id: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action: None | str | Unset
        if isinstance(self.action, Unset):
            action = UNSET
        else:
            action = self.action

        dashboard_id: int | None | Unset
        if isinstance(self.dashboard_id, Unset):
            dashboard_id = UNSET
        else:
            dashboard_id = self.dashboard_id

        dttm: None | str | Unset
        if isinstance(self.dttm, Unset):
            dttm = UNSET
        elif isinstance(self.dttm, datetime.datetime):
            dttm = self.dttm.isoformat()
        else:
            dttm = self.dttm

        duration_ms: int | None | Unset
        if isinstance(self.duration_ms, Unset):
            duration_ms = UNSET
        else:
            duration_ms = self.duration_ms

        json: None | str | Unset
        if isinstance(self.json, Unset):
            json = UNSET
        else:
            json = self.json

        referrer: None | str | Unset
        if isinstance(self.referrer, Unset):
            referrer = UNSET
        else:
            referrer = self.referrer

        slice_id: int | None | Unset
        if isinstance(self.slice_id, Unset):
            slice_id = UNSET
        else:
            slice_id = self.slice_id

        user: dict[str, Any] | Unset = UNSET
        if not isinstance(self.user, Unset):
            user = self.user.to_dict()

        user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if action is not UNSET:
            field_dict["action"] = action
        if dashboard_id is not UNSET:
            field_dict["dashboard_id"] = dashboard_id
        if dttm is not UNSET:
            field_dict["dttm"] = dttm
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if json is not UNSET:
            field_dict["json"] = json
        if referrer is not UNSET:
            field_dict["referrer"] = referrer
        if slice_id is not UNSET:
            field_dict["slice_id"] = slice_id
        if user is not UNSET:
            field_dict["user"] = user
        if user_id is not UNSET:
            field_dict["user_id"] = user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.log_rest_api_get_user import LogRestApiGetUser

        d = dict(src_dict)

        def _parse_action(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        action = _parse_action(d.pop("action", UNSET))

        def _parse_dashboard_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        dashboard_id = _parse_dashboard_id(d.pop("dashboard_id", UNSET))

        def _parse_dttm(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                dttm_type_0 = isoparse(data)

                return dttm_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        dttm = _parse_dttm(d.pop("dttm", UNSET))

        def _parse_duration_ms(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        duration_ms = _parse_duration_ms(d.pop("duration_ms", UNSET))

        def _parse_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        json = _parse_json(d.pop("json", UNSET))

        def _parse_referrer(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        referrer = _parse_referrer(d.pop("referrer", UNSET))

        def _parse_slice_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        slice_id = _parse_slice_id(d.pop("slice_id", UNSET))

        _user = d.pop("user", UNSET)
        user: LogRestApiGetUser | Unset
        if isinstance(_user, Unset):
            user = UNSET
        else:
            user = LogRestApiGetUser.from_dict(_user)

        user_id = d.pop("user_id", UNSET)

        log_rest_api_get = cls(
            action=action,
            dashboard_id=dashboard_id,
            dttm=dttm,
            duration_ms=duration_ms,
            json=json,
            referrer=referrer,
            slice_id=slice_id,
            user=user,
            user_id=user_id,
        )

        log_rest_api_get.additional_properties = d
        return log_rest_api_get

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

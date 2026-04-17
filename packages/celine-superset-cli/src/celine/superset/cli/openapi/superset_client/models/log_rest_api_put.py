from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogRestApiPut")


@_attrs_define
class LogRestApiPut:
    """
    Attributes:
        action (None | str | Unset):
        dttm (datetime.datetime | None | Unset):
        json (None | str | Unset):
        user (Any | Unset):
    """

    action: None | str | Unset = UNSET
    dttm: datetime.datetime | None | Unset = UNSET
    json: None | str | Unset = UNSET
    user: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action: None | str | Unset
        if isinstance(self.action, Unset):
            action = UNSET
        else:
            action = self.action

        dttm: None | str | Unset
        if isinstance(self.dttm, Unset):
            dttm = UNSET
        elif isinstance(self.dttm, datetime.datetime):
            dttm = self.dttm.isoformat()
        else:
            dttm = self.dttm

        json: None | str | Unset
        if isinstance(self.json, Unset):
            json = UNSET
        else:
            json = self.json

        user = self.user

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if action is not UNSET:
            field_dict["action"] = action
        if dttm is not UNSET:
            field_dict["dttm"] = dttm
        if json is not UNSET:
            field_dict["json"] = json
        if user is not UNSET:
            field_dict["user"] = user

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_action(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        action = _parse_action(d.pop("action", UNSET))

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

        def _parse_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        json = _parse_json(d.pop("json", UNSET))

        user = d.pop("user", UNSET)

        log_rest_api_put = cls(
            action=action,
            dttm=dttm,
            json=json,
            user=user,
        )

        log_rest_api_put.additional_properties = d
        return log_rest_api_put

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

from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="UserRegistrationsRestAPIGetList")


@_attrs_define
class UserRegistrationsRestAPIGetList:
    """
    Attributes:
        email (str):
        first_name (str):
        last_name (str):
        username (str):
        id (int | Unset):
        registration_date (datetime.datetime | None | Unset):
        registration_hash (None | str | Unset):
    """

    email: str
    first_name: str
    last_name: str
    username: str
    id: int | Unset = UNSET
    registration_date: datetime.datetime | None | Unset = UNSET
    registration_hash: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        first_name = self.first_name

        last_name = self.last_name

        username = self.username

        id = self.id

        registration_date: None | str | Unset
        if isinstance(self.registration_date, Unset):
            registration_date = UNSET
        elif isinstance(self.registration_date, datetime.datetime):
            registration_date = self.registration_date.isoformat()
        else:
            registration_date = self.registration_date

        registration_hash: None | str | Unset
        if isinstance(self.registration_hash, Unset):
            registration_hash = UNSET
        else:
            registration_hash = self.registration_hash

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "username": username,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if registration_date is not UNSET:
            field_dict["registration_date"] = registration_date
        if registration_hash is not UNSET:
            field_dict["registration_hash"] = registration_hash

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email")

        first_name = d.pop("first_name")

        last_name = d.pop("last_name")

        username = d.pop("username")

        id = d.pop("id", UNSET)

        def _parse_registration_date(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                registration_date_type_0 = isoparse(data)

                return registration_date_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        registration_date = _parse_registration_date(d.pop("registration_date", UNSET))

        def _parse_registration_hash(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        registration_hash = _parse_registration_hash(d.pop("registration_hash", UNSET))

        user_registrations_rest_api_get_list = cls(
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            id=id,
            registration_date=registration_date,
            registration_hash=registration_hash,
        )

        user_registrations_rest_api_get_list.additional_properties = d
        return user_registrations_rest_api_get_list

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UserResponseSchema")


@_attrs_define
class UserResponseSchema:
    """
    Attributes:
        email (str | Unset):
        first_name (str | Unset):
        id (int | Unset):
        is_active (bool | Unset):
        is_anonymous (bool | Unset):
        last_name (str | Unset):
        login_count (int | Unset):
        username (str | Unset):
    """

    email: str | Unset = UNSET
    first_name: str | Unset = UNSET
    id: int | Unset = UNSET
    is_active: bool | Unset = UNSET
    is_anonymous: bool | Unset = UNSET
    last_name: str | Unset = UNSET
    login_count: int | Unset = UNSET
    username: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        first_name = self.first_name

        id = self.id

        is_active = self.is_active

        is_anonymous = self.is_anonymous

        last_name = self.last_name

        login_count = self.login_count

        username = self.username

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if email is not UNSET:
            field_dict["email"] = email
        if first_name is not UNSET:
            field_dict["first_name"] = first_name
        if id is not UNSET:
            field_dict["id"] = id
        if is_active is not UNSET:
            field_dict["is_active"] = is_active
        if is_anonymous is not UNSET:
            field_dict["is_anonymous"] = is_anonymous
        if last_name is not UNSET:
            field_dict["last_name"] = last_name
        if login_count is not UNSET:
            field_dict["login_count"] = login_count
        if username is not UNSET:
            field_dict["username"] = username

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email", UNSET)

        first_name = d.pop("first_name", UNSET)

        id = d.pop("id", UNSET)

        is_active = d.pop("is_active", UNSET)

        is_anonymous = d.pop("is_anonymous", UNSET)

        last_name = d.pop("last_name", UNSET)

        login_count = d.pop("login_count", UNSET)

        username = d.pop("username", UNSET)

        user_response_schema = cls(
            email=email,
            first_name=first_name,
            id=id,
            is_active=is_active,
            is_anonymous=is_anonymous,
            last_name=last_name,
            login_count=login_count,
            username=username,
        )

        user_response_schema.additional_properties = d
        return user_response_schema

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

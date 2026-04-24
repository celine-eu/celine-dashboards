from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SupersetUserApiPut")


@_attrs_define
class SupersetUserApiPut:
    """
    Attributes:
        active (bool | Unset): Is user active?It's not a good policy to remove a user, just make it inactive
        email (str | Unset): The user's email
        first_name (str | Unset): The user's first name
        groups (list[int] | Unset): The user's roles
        last_name (str | Unset): The user's last name
        password (str | Unset): The user's password for authentication
        roles (list[int] | Unset): The user's roles
        username (str | Unset): The user's username
    """

    active: bool | Unset = UNSET
    email: str | Unset = UNSET
    first_name: str | Unset = UNSET
    groups: list[int] | Unset = UNSET
    last_name: str | Unset = UNSET
    password: str | Unset = UNSET
    roles: list[int] | Unset = UNSET
    username: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        active = self.active

        email = self.email

        first_name = self.first_name

        groups: list[int] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        last_name = self.last_name

        password = self.password

        roles: list[int] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles

        username = self.username

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if active is not UNSET:
            field_dict["active"] = active
        if email is not UNSET:
            field_dict["email"] = email
        if first_name is not UNSET:
            field_dict["first_name"] = first_name
        if groups is not UNSET:
            field_dict["groups"] = groups
        if last_name is not UNSET:
            field_dict["last_name"] = last_name
        if password is not UNSET:
            field_dict["password"] = password
        if roles is not UNSET:
            field_dict["roles"] = roles
        if username is not UNSET:
            field_dict["username"] = username

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        active = d.pop("active", UNSET)

        email = d.pop("email", UNSET)

        first_name = d.pop("first_name", UNSET)

        groups = cast(list[int], d.pop("groups", UNSET))

        last_name = d.pop("last_name", UNSET)

        password = d.pop("password", UNSET)

        roles = cast(list[int], d.pop("roles", UNSET))

        username = d.pop("username", UNSET)

        superset_user_api_put = cls(
            active=active,
            email=email,
            first_name=first_name,
            groups=groups,
            last_name=last_name,
            password=password,
            roles=roles,
            username=username,
        )

        superset_user_api_put.additional_properties = d
        return superset_user_api_put

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

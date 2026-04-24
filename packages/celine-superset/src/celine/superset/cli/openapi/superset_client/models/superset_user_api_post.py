from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SupersetUserApiPost")


@_attrs_define
class SupersetUserApiPost:
    """
    Attributes:
        email (str): The user's email
        first_name (str): The user's first name
        last_name (str): The user's last name
        password (str): The user's password for authentication
        username (str): The user's username
        active (bool | Unset): Is user active?It's not a good policy to remove a user, just make it inactive
        groups (list[int] | Unset): The user's roles
        roles (list[int] | Unset): The user's roles
    """

    email: str
    first_name: str
    last_name: str
    password: str
    username: str
    active: bool | Unset = UNSET
    groups: list[int] | Unset = UNSET
    roles: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        first_name = self.first_name

        last_name = self.last_name

        password = self.password

        username = self.username

        active = self.active

        groups: list[int] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        roles: list[int] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "password": password,
                "username": username,
            }
        )
        if active is not UNSET:
            field_dict["active"] = active
        if groups is not UNSET:
            field_dict["groups"] = groups
        if roles is not UNSET:
            field_dict["roles"] = roles

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email")

        first_name = d.pop("first_name")

        last_name = d.pop("last_name")

        password = d.pop("password")

        username = d.pop("username")

        active = d.pop("active", UNSET)

        groups = cast(list[int], d.pop("groups", UNSET))

        roles = cast(list[int], d.pop("roles", UNSET))

        superset_user_api_post = cls(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            username=username,
            active=active,
            groups=groups,
            roles=roles,
        )

        superset_user_api_post.additional_properties = d
        return superset_user_api_post

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

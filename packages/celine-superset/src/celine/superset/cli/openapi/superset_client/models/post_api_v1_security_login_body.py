from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.post_api_v1_security_login_body_provider import (
    PostApiV1SecurityLoginBodyProvider,
    check_post_api_v1_security_login_body_provider,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="PostApiV1SecurityLoginBody")


@_attrs_define
class PostApiV1SecurityLoginBody:
    """
    Attributes:
        password (str | Unset): The password for authentication Example: complex-password.
        provider (PostApiV1SecurityLoginBodyProvider | Unset): Choose an authentication provider Example: db.
        refresh (bool | Unset): If true a refresh token is provided also Example: True.
        username (str | Unset): The username for authentication Example: admin.
    """

    password: str | Unset = UNSET
    provider: PostApiV1SecurityLoginBodyProvider | Unset = UNSET
    refresh: bool | Unset = UNSET
    username: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        password = self.password

        provider: str | Unset = UNSET
        if not isinstance(self.provider, Unset):
            provider = self.provider

        refresh = self.refresh

        username = self.username

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if password is not UNSET:
            field_dict["password"] = password
        if provider is not UNSET:
            field_dict["provider"] = provider
        if refresh is not UNSET:
            field_dict["refresh"] = refresh
        if username is not UNSET:
            field_dict["username"] = username

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        password = d.pop("password", UNSET)

        _provider = d.pop("provider", UNSET)
        provider: PostApiV1SecurityLoginBodyProvider | Unset
        if isinstance(_provider, Unset):
            provider = UNSET
        else:
            provider = check_post_api_v1_security_login_body_provider(_provider)

        refresh = d.pop("refresh", UNSET)

        username = d.pop("username", UNSET)

        post_api_v1_security_login_body = cls(
            password=password,
            provider=provider,
            refresh=refresh,
            username=username,
        )

        post_api_v1_security_login_body.additional_properties = d
        return post_api_v1_security_login_body

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

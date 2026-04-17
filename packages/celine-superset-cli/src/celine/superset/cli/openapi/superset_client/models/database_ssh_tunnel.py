from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatabaseSSHTunnel")


@_attrs_define
class DatabaseSSHTunnel:
    """
    Attributes:
        id (int | None | Unset): SSH Tunnel ID (for updates)
        password (str | Unset):
        private_key (str | Unset):
        private_key_password (str | Unset):
        server_address (str | Unset):
        server_port (int | Unset):
        username (str | Unset):
    """

    id: int | None | Unset = UNSET
    password: str | Unset = UNSET
    private_key: str | Unset = UNSET
    private_key_password: str | Unset = UNSET
    server_address: str | Unset = UNSET
    server_port: int | Unset = UNSET
    username: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id: int | None | Unset
        if isinstance(self.id, Unset):
            id = UNSET
        else:
            id = self.id

        password = self.password

        private_key = self.private_key

        private_key_password = self.private_key_password

        server_address = self.server_address

        server_port = self.server_port

        username = self.username

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if password is not UNSET:
            field_dict["password"] = password
        if private_key is not UNSET:
            field_dict["private_key"] = private_key
        if private_key_password is not UNSET:
            field_dict["private_key_password"] = private_key_password
        if server_address is not UNSET:
            field_dict["server_address"] = server_address
        if server_port is not UNSET:
            field_dict["server_port"] = server_port
        if username is not UNSET:
            field_dict["username"] = username

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        id = _parse_id(d.pop("id", UNSET))

        password = d.pop("password", UNSET)

        private_key = d.pop("private_key", UNSET)

        private_key_password = d.pop("private_key_password", UNSET)

        server_address = d.pop("server_address", UNSET)

        server_port = d.pop("server_port", UNSET)

        username = d.pop("username", UNSET)

        database_ssh_tunnel = cls(
            id=id,
            password=password,
            private_key=private_key,
            private_key_password=private_key_password,
            server_address=server_address,
            server_port=server_port,
            username=username,
        )

        database_ssh_tunnel.additional_properties = d
        return database_ssh_tunnel

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

from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from .. import types
from ..types import UNSET, File, FileTypes, Unset

T = TypeVar("T", bound="PostApiV1AssetsImportBody")


@_attrs_define
class PostApiV1AssetsImportBody:
    """
    Attributes:
        bundle (File | Unset): upload file (ZIP or JSON)
        passwords (str | Unset): JSON map of passwords for each featured database in the ZIP file. If the ZIP includes a
            database config in the path `databases/MyDatabase.yaml`, the password should be provided in the following
            format: `{"databases/MyDatabase.yaml": "my_password"}`.
        sparse (bool | Unset): allow sparse update of resources
        ssh_tunnel_passwords (str | Unset): JSON map of passwords for each ssh_tunnel associated to a featured database
            in the ZIP file. If the ZIP includes a ssh_tunnel config in the path `databases/MyDatabase.yaml`, the password
            should be provided in the following format: `{"databases/MyDatabase.yaml": "my_password"}`.
        ssh_tunnel_private_key_passwords (str | Unset): JSON map of private_key_passwords for each ssh_tunnel associated
            to a featured database in the ZIP file. If the ZIP includes a ssh_tunnel config in the path
            `databases/MyDatabase.yaml`, the private_key should be provided in the following format:
            `{"databases/MyDatabase.yaml": "my_private_key_password"}`.
        ssh_tunnel_private_keys (str | Unset): JSON map of private_keys for each ssh_tunnel associated to a featured
            database in the ZIP file. If the ZIP includes a ssh_tunnel config in the path `databases/MyDatabase.yaml`, the
            private_key should be provided in the following format: `{"databases/MyDatabase.yaml": "my_private_key"}`.
    """

    bundle: File | Unset = UNSET
    passwords: str | Unset = UNSET
    sparse: bool | Unset = UNSET
    ssh_tunnel_passwords: str | Unset = UNSET
    ssh_tunnel_private_key_passwords: str | Unset = UNSET
    ssh_tunnel_private_keys: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bundle: FileTypes | Unset = UNSET
        if not isinstance(self.bundle, Unset):
            bundle = self.bundle.to_tuple()

        passwords = self.passwords

        sparse = self.sparse

        ssh_tunnel_passwords = self.ssh_tunnel_passwords

        ssh_tunnel_private_key_passwords = self.ssh_tunnel_private_key_passwords

        ssh_tunnel_private_keys = self.ssh_tunnel_private_keys

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if bundle is not UNSET:
            field_dict["bundle"] = bundle
        if passwords is not UNSET:
            field_dict["passwords"] = passwords
        if sparse is not UNSET:
            field_dict["sparse"] = sparse
        if ssh_tunnel_passwords is not UNSET:
            field_dict["ssh_tunnel_passwords"] = ssh_tunnel_passwords
        if ssh_tunnel_private_key_passwords is not UNSET:
            field_dict["ssh_tunnel_private_key_passwords"] = ssh_tunnel_private_key_passwords
        if ssh_tunnel_private_keys is not UNSET:
            field_dict["ssh_tunnel_private_keys"] = ssh_tunnel_private_keys

        return field_dict

    def to_multipart(self) -> types.RequestFiles:
        files: types.RequestFiles = []

        if not isinstance(self.bundle, Unset):
            files.append(("bundle", self.bundle.to_tuple()))

        if not isinstance(self.passwords, Unset):
            files.append(("passwords", (None, str(self.passwords).encode(), "text/plain")))

        if not isinstance(self.sparse, Unset):
            files.append(("sparse", (None, str(self.sparse).encode(), "text/plain")))

        if not isinstance(self.ssh_tunnel_passwords, Unset):
            files.append(("ssh_tunnel_passwords", (None, str(self.ssh_tunnel_passwords).encode(), "text/plain")))

        if not isinstance(self.ssh_tunnel_private_key_passwords, Unset):
            files.append(
                (
                    "ssh_tunnel_private_key_passwords",
                    (None, str(self.ssh_tunnel_private_key_passwords).encode(), "text/plain"),
                )
            )

        if not isinstance(self.ssh_tunnel_private_keys, Unset):
            files.append(("ssh_tunnel_private_keys", (None, str(self.ssh_tunnel_private_keys).encode(), "text/plain")))

        for prop_name, prop in self.additional_properties.items():
            files.append((prop_name, (None, str(prop).encode(), "text/plain")))

        return files

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _bundle = d.pop("bundle", UNSET)
        bundle: File | Unset
        if isinstance(_bundle, Unset):
            bundle = UNSET
        else:
            bundle = File(payload=BytesIO(_bundle))

        passwords = d.pop("passwords", UNSET)

        sparse = d.pop("sparse", UNSET)

        ssh_tunnel_passwords = d.pop("ssh_tunnel_passwords", UNSET)

        ssh_tunnel_private_key_passwords = d.pop("ssh_tunnel_private_key_passwords", UNSET)

        ssh_tunnel_private_keys = d.pop("ssh_tunnel_private_keys", UNSET)

        post_api_v1_assets_import_body = cls(
            bundle=bundle,
            passwords=passwords,
            sparse=sparse,
            ssh_tunnel_passwords=ssh_tunnel_passwords,
            ssh_tunnel_private_key_passwords=ssh_tunnel_private_key_passwords,
            ssh_tunnel_private_keys=ssh_tunnel_private_keys,
        )

        post_api_v1_assets_import_body.additional_properties = d
        return post_api_v1_assets_import_body

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

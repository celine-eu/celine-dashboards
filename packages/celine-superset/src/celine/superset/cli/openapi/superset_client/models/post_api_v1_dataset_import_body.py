from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from .. import types
from ..types import UNSET, File, FileTypes, Unset

T = TypeVar("T", bound="PostApiV1DatasetImportBody")


@_attrs_define
class PostApiV1DatasetImportBody:
    """
    Attributes:
        form_data (File | Unset): upload file (ZIP or YAML)
        overwrite (bool | Unset): overwrite existing datasets?
        passwords (str | Unset): JSON map of passwords for each featured database in the ZIP file. If the ZIP includes a
            database config in the path `databases/MyDatabase.yaml`, the password should be provided in the following
            format: `{"databases/MyDatabase.yaml": "my_password"}`.
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
        sync_columns (bool | Unset): sync columns?
        sync_metrics (bool | Unset): sync metrics?
    """

    form_data: File | Unset = UNSET
    overwrite: bool | Unset = UNSET
    passwords: str | Unset = UNSET
    ssh_tunnel_passwords: str | Unset = UNSET
    ssh_tunnel_private_key_passwords: str | Unset = UNSET
    ssh_tunnel_private_keys: str | Unset = UNSET
    sync_columns: bool | Unset = UNSET
    sync_metrics: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        form_data: FileTypes | Unset = UNSET
        if not isinstance(self.form_data, Unset):
            form_data = self.form_data.to_tuple()

        overwrite = self.overwrite

        passwords = self.passwords

        ssh_tunnel_passwords = self.ssh_tunnel_passwords

        ssh_tunnel_private_key_passwords = self.ssh_tunnel_private_key_passwords

        ssh_tunnel_private_keys = self.ssh_tunnel_private_keys

        sync_columns = self.sync_columns

        sync_metrics = self.sync_metrics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if form_data is not UNSET:
            field_dict["formData"] = form_data
        if overwrite is not UNSET:
            field_dict["overwrite"] = overwrite
        if passwords is not UNSET:
            field_dict["passwords"] = passwords
        if ssh_tunnel_passwords is not UNSET:
            field_dict["ssh_tunnel_passwords"] = ssh_tunnel_passwords
        if ssh_tunnel_private_key_passwords is not UNSET:
            field_dict["ssh_tunnel_private_key_passwords"] = ssh_tunnel_private_key_passwords
        if ssh_tunnel_private_keys is not UNSET:
            field_dict["ssh_tunnel_private_keys"] = ssh_tunnel_private_keys
        if sync_columns is not UNSET:
            field_dict["sync_columns"] = sync_columns
        if sync_metrics is not UNSET:
            field_dict["sync_metrics"] = sync_metrics

        return field_dict

    def to_multipart(self) -> types.RequestFiles:
        files: types.RequestFiles = []

        if not isinstance(self.form_data, Unset):
            files.append(("formData", self.form_data.to_tuple()))

        if not isinstance(self.overwrite, Unset):
            files.append(("overwrite", (None, str(self.overwrite).encode(), "text/plain")))

        if not isinstance(self.passwords, Unset):
            files.append(("passwords", (None, str(self.passwords).encode(), "text/plain")))

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

        if not isinstance(self.sync_columns, Unset):
            files.append(("sync_columns", (None, str(self.sync_columns).encode(), "text/plain")))

        if not isinstance(self.sync_metrics, Unset):
            files.append(("sync_metrics", (None, str(self.sync_metrics).encode(), "text/plain")))

        for prop_name, prop in self.additional_properties.items():
            files.append((prop_name, (None, str(prop).encode(), "text/plain")))

        return files

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _form_data = d.pop("formData", UNSET)
        form_data: File | Unset
        if isinstance(_form_data, Unset):
            form_data = UNSET
        else:
            form_data = File(payload=BytesIO(_form_data))

        overwrite = d.pop("overwrite", UNSET)

        passwords = d.pop("passwords", UNSET)

        ssh_tunnel_passwords = d.pop("ssh_tunnel_passwords", UNSET)

        ssh_tunnel_private_key_passwords = d.pop("ssh_tunnel_private_key_passwords", UNSET)

        ssh_tunnel_private_keys = d.pop("ssh_tunnel_private_keys", UNSET)

        sync_columns = d.pop("sync_columns", UNSET)

        sync_metrics = d.pop("sync_metrics", UNSET)

        post_api_v1_dataset_import_body = cls(
            form_data=form_data,
            overwrite=overwrite,
            passwords=passwords,
            ssh_tunnel_passwords=ssh_tunnel_passwords,
            ssh_tunnel_private_key_passwords=ssh_tunnel_private_key_passwords,
            ssh_tunnel_private_keys=ssh_tunnel_private_keys,
            sync_columns=sync_columns,
            sync_metrics=sync_metrics,
        )

        post_api_v1_dataset_import_body.additional_properties = d
        return post_api_v1_dataset_import_body

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

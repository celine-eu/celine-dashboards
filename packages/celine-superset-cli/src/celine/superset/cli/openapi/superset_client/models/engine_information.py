from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EngineInformation")


@_attrs_define
class EngineInformation:
    """
    Attributes:
        disable_ssh_tunneling (bool | Unset): SSH tunnel is not available to the database
        supports_dynamic_catalog (bool | Unset): The database supports multiple catalogs in a single connection
        supports_file_upload (bool | Unset): Users can upload files to the database
        supports_oauth2 (bool | Unset): The database supports OAuth2
    """

    disable_ssh_tunneling: bool | Unset = UNSET
    supports_dynamic_catalog: bool | Unset = UNSET
    supports_file_upload: bool | Unset = UNSET
    supports_oauth2: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        disable_ssh_tunneling = self.disable_ssh_tunneling

        supports_dynamic_catalog = self.supports_dynamic_catalog

        supports_file_upload = self.supports_file_upload

        supports_oauth2 = self.supports_oauth2

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if disable_ssh_tunneling is not UNSET:
            field_dict["disable_ssh_tunneling"] = disable_ssh_tunneling
        if supports_dynamic_catalog is not UNSET:
            field_dict["supports_dynamic_catalog"] = supports_dynamic_catalog
        if supports_file_upload is not UNSET:
            field_dict["supports_file_upload"] = supports_file_upload
        if supports_oauth2 is not UNSET:
            field_dict["supports_oauth2"] = supports_oauth2

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        disable_ssh_tunneling = d.pop("disable_ssh_tunneling", UNSET)

        supports_dynamic_catalog = d.pop("supports_dynamic_catalog", UNSET)

        supports_file_upload = d.pop("supports_file_upload", UNSET)

        supports_oauth2 = d.pop("supports_oauth2", UNSET)

        engine_information = cls(
            disable_ssh_tunneling=disable_ssh_tunneling,
            supports_dynamic_catalog=supports_dynamic_catalog,
            supports_file_upload=supports_file_upload,
            supports_oauth2=supports_oauth2,
        )

        engine_information.additional_properties = d
        return engine_information

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

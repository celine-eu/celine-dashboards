from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GetApiV1DatabaseAvailableResponse200ItemEngineInformation")


@_attrs_define
class GetApiV1DatabaseAvailableResponse200ItemEngineInformation:
    """Dict with public properties form the DB Engine

    Attributes:
        disable_ssh_tunneling (bool | Unset): Whether the engine supports SSH Tunnels
        supports_file_upload (bool | Unset): Whether the engine supports file uploads
    """

    disable_ssh_tunneling: bool | Unset = UNSET
    supports_file_upload: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        disable_ssh_tunneling = self.disable_ssh_tunneling

        supports_file_upload = self.supports_file_upload

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if disable_ssh_tunneling is not UNSET:
            field_dict["disable_ssh_tunneling"] = disable_ssh_tunneling
        if supports_file_upload is not UNSET:
            field_dict["supports_file_upload"] = supports_file_upload

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        disable_ssh_tunneling = d.pop("disable_ssh_tunneling", UNSET)

        supports_file_upload = d.pop("supports_file_upload", UNSET)

        get_api_v1_database_available_response_200_item_engine_information = cls(
            disable_ssh_tunneling=disable_ssh_tunneling,
            supports_file_upload=supports_file_upload,
        )

        get_api_v1_database_available_response_200_item_engine_information.additional_properties = d
        return get_api_v1_database_available_response_200_item_engine_information

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TableMetadataOptionsResponse")


@_attrs_define
class TableMetadataOptionsResponse:
    """
    Attributes:
        deferrable (bool | Unset):
        initially (bool | Unset):
        match (bool | Unset):
        ondelete (bool | Unset):
        onupdate (bool | Unset):
    """

    deferrable: bool | Unset = UNSET
    initially: bool | Unset = UNSET
    match: bool | Unset = UNSET
    ondelete: bool | Unset = UNSET
    onupdate: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        deferrable = self.deferrable

        initially = self.initially

        match = self.match

        ondelete = self.ondelete

        onupdate = self.onupdate

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if deferrable is not UNSET:
            field_dict["deferrable"] = deferrable
        if initially is not UNSET:
            field_dict["initially"] = initially
        if match is not UNSET:
            field_dict["match"] = match
        if ondelete is not UNSET:
            field_dict["ondelete"] = ondelete
        if onupdate is not UNSET:
            field_dict["onupdate"] = onupdate

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        deferrable = d.pop("deferrable", UNSET)

        initially = d.pop("initially", UNSET)

        match = d.pop("match", UNSET)

        ondelete = d.pop("ondelete", UNSET)

        onupdate = d.pop("onupdate", UNSET)

        table_metadata_options_response = cls(
            deferrable=deferrable,
            initially=initially,
            match=match,
            ondelete=ondelete,
            onupdate=onupdate,
        )

        table_metadata_options_response.additional_properties = d
        return table_metadata_options_response

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

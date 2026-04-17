from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportRecipientConfigJSON")


@_attrs_define
class ReportRecipientConfigJSON:
    """
    Attributes:
        bcc_target (str | Unset):
        cc_target (str | Unset):
        target (str | Unset):
    """

    bcc_target: str | Unset = UNSET
    cc_target: str | Unset = UNSET
    target: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bcc_target = self.bcc_target

        cc_target = self.cc_target

        target = self.target

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if bcc_target is not UNSET:
            field_dict["bccTarget"] = bcc_target
        if cc_target is not UNSET:
            field_dict["ccTarget"] = cc_target
        if target is not UNSET:
            field_dict["target"] = target

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bcc_target = d.pop("bccTarget", UNSET)

        cc_target = d.pop("ccTarget", UNSET)

        target = d.pop("target", UNSET)

        report_recipient_config_json = cls(
            bcc_target=bcc_target,
            cc_target=cc_target,
            target=target,
        )

        report_recipient_config_json.additional_properties = d
        return report_recipient_config_json

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.report_recipient_type import ReportRecipientType, check_report_recipient_type
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.report_recipient_config_json import ReportRecipientConfigJSON


T = TypeVar("T", bound="ReportRecipient")


@_attrs_define
class ReportRecipient:
    """
    Attributes:
        type_ (ReportRecipientType): The recipient type, check spec for valid options
        recipient_config_json (ReportRecipientConfigJSON | Unset):
    """

    type_: ReportRecipientType
    recipient_config_json: ReportRecipientConfigJSON | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_: str = self.type_

        recipient_config_json: dict[str, Any] | Unset = UNSET
        if not isinstance(self.recipient_config_json, Unset):
            recipient_config_json = self.recipient_config_json.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
            }
        )
        if recipient_config_json is not UNSET:
            field_dict["recipient_config_json"] = recipient_config_json

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.report_recipient_config_json import ReportRecipientConfigJSON

        d = dict(src_dict)
        type_ = check_report_recipient_type(d.pop("type"))

        _recipient_config_json = d.pop("recipient_config_json", UNSET)
        recipient_config_json: ReportRecipientConfigJSON | Unset
        if isinstance(_recipient_config_json, Unset):
            recipient_config_json = UNSET
        else:
            recipient_config_json = ReportRecipientConfigJSON.from_dict(_recipient_config_json)

        report_recipient = cls(
            type_=type_,
            recipient_config_json=recipient_config_json,
        )

        report_recipient.additional_properties = d
        return report_recipient

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

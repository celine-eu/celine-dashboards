from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.related_result_response_extra import RelatedResultResponseExtra


T = TypeVar("T", bound="RelatedResultResponse")


@_attrs_define
class RelatedResultResponse:
    """
    Attributes:
        extra (RelatedResultResponseExtra | Unset): The extra metadata for related item
        text (str | Unset): The related item string representation
        value (int | Unset): The related item identifier
    """

    extra: RelatedResultResponseExtra | Unset = UNSET
    text: str | Unset = UNSET
    value: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        text = self.text

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if extra is not UNSET:
            field_dict["extra"] = extra
        if text is not UNSET:
            field_dict["text"] = text
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.related_result_response_extra import RelatedResultResponseExtra

        d = dict(src_dict)
        _extra = d.pop("extra", UNSET)
        extra: RelatedResultResponseExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = RelatedResultResponseExtra.from_dict(_extra)

        text = d.pop("text", UNSET)

        value = d.pop("value", UNSET)

        related_result_response = cls(
            extra=extra,
            text=text,
            value=value,
        )

        related_result_response.additional_properties = d
        return related_result_response

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

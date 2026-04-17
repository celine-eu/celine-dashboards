from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdvancedDataTypeSchema")


@_attrs_define
class AdvancedDataTypeSchema:
    """
    Attributes:
        display_value (str | Unset): The string representation of the parsed values
        error_message (str | Unset):
        valid_filter_operators (list[str] | Unset):
        values (list[str] | Unset):
    """

    display_value: str | Unset = UNSET
    error_message: str | Unset = UNSET
    valid_filter_operators: list[str] | Unset = UNSET
    values: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        display_value = self.display_value

        error_message = self.error_message

        valid_filter_operators: list[str] | Unset = UNSET
        if not isinstance(self.valid_filter_operators, Unset):
            valid_filter_operators = self.valid_filter_operators

        values: list[str] | Unset = UNSET
        if not isinstance(self.values, Unset):
            values = self.values

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if display_value is not UNSET:
            field_dict["display_value"] = display_value
        if error_message is not UNSET:
            field_dict["error_message"] = error_message
        if valid_filter_operators is not UNSET:
            field_dict["valid_filter_operators"] = valid_filter_operators
        if values is not UNSET:
            field_dict["values"] = values

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        display_value = d.pop("display_value", UNSET)

        error_message = d.pop("error_message", UNSET)

        valid_filter_operators = cast(list[str], d.pop("valid_filter_operators", UNSET))

        values = cast(list[str], d.pop("values", UNSET))

        advanced_data_type_schema = cls(
            display_value=display_value,
            error_message=error_message,
            valid_filter_operators=valid_filter_operators,
            values=values,
        )

        advanced_data_type_schema.additional_properties = d
        return advanced_data_type_schema

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

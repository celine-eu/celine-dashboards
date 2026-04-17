from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ValidateSQLResponse")


@_attrs_define
class ValidateSQLResponse:
    """
    Attributes:
        end_column (int | Unset):
        line_number (int | Unset):
        message (str | Unset):
        start_column (int | Unset):
    """

    end_column: int | Unset = UNSET
    line_number: int | Unset = UNSET
    message: str | Unset = UNSET
    start_column: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        end_column = self.end_column

        line_number = self.line_number

        message = self.message

        start_column = self.start_column

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if end_column is not UNSET:
            field_dict["end_column"] = end_column
        if line_number is not UNSET:
            field_dict["line_number"] = line_number
        if message is not UNSET:
            field_dict["message"] = message
        if start_column is not UNSET:
            field_dict["start_column"] = start_column

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        end_column = d.pop("end_column", UNSET)

        line_number = d.pop("line_number", UNSET)

        message = d.pop("message", UNSET)

        start_column = d.pop("start_column", UNSET)

        validate_sql_response = cls(
            end_column=end_column,
            line_number=line_number,
            message=message,
            start_column=start_column,
        )

        validate_sql_response.additional_properties = d
        return validate_sql_response

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

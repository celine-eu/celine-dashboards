from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatabaseFunctionNamesResponse")


@_attrs_define
class DatabaseFunctionNamesResponse:
    """
    Attributes:
        function_names (list[str] | Unset):
    """

    function_names: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        function_names: list[str] | Unset = UNSET
        if not isinstance(self.function_names, Unset):
            function_names = self.function_names

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if function_names is not UNSET:
            field_dict["function_names"] = function_names

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        function_names = cast(list[str], d.pop("function_names", UNSET))

        database_function_names_response = cls(
            function_names=function_names,
        )

        database_function_names_response.additional_properties = d
        return database_function_names_response

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

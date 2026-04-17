from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="GetListSchemaFiltersItem")


@_attrs_define
class GetListSchemaFiltersItem:
    """
    Attributes:
        col (str):
        opr (str):
        value (bool | float | list[bool | float | str] | str):
    """

    col: str
    opr: str
    value: bool | float | list[bool | float | str] | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        col = self.col

        opr = self.opr

        value: bool | float | list[bool | float | str] | str
        if isinstance(self.value, list):
            value = []
            for value_type_3_item_data in self.value:
                value_type_3_item: bool | float | str
                value_type_3_item = value_type_3_item_data
                value.append(value_type_3_item)

        else:
            value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "col": col,
                "opr": opr,
                "value": value,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        col = d.pop("col")

        opr = d.pop("opr")

        def _parse_value(data: object) -> bool | float | list[bool | float | str] | str:
            try:
                if not isinstance(data, list):
                    raise TypeError()
                value_type_3 = []
                _value_type_3 = data
                for value_type_3_item_data in _value_type_3:

                    def _parse_value_type_3_item(data: object) -> bool | float | str:
                        return cast(bool | float | str, data)

                    value_type_3_item = _parse_value_type_3_item(value_type_3_item_data)

                    value_type_3.append(value_type_3_item)

                return value_type_3
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(bool | float | list[bool | float | str] | str, data)

        value = _parse_value(d.pop("value"))

        get_list_schema_filters_item = cls(
            col=col,
            opr=opr,
            value=value,
        )

        get_list_schema_filters_item.additional_properties = d
        return get_list_schema_filters_item

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataRestApiGetListSqlaTable")


@_attrs_define
class ChartDataRestApiGetListSqlaTable:
    """
    Attributes:
        table_name (str):
        default_endpoint (None | str | Unset):
    """

    table_name: str
    default_endpoint: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        table_name = self.table_name

        default_endpoint: None | str | Unset
        if isinstance(self.default_endpoint, Unset):
            default_endpoint = UNSET
        else:
            default_endpoint = self.default_endpoint

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "table_name": table_name,
            }
        )
        if default_endpoint is not UNSET:
            field_dict["default_endpoint"] = default_endpoint

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        table_name = d.pop("table_name")

        def _parse_default_endpoint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        default_endpoint = _parse_default_endpoint(d.pop("default_endpoint", UNSET))

        chart_data_rest_api_get_list_sqla_table = cls(
            table_name=table_name,
            default_endpoint=default_endpoint,
        )

        chart_data_rest_api_get_list_sqla_table.additional_properties = d
        return chart_data_rest_api_get_list_sqla_table

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

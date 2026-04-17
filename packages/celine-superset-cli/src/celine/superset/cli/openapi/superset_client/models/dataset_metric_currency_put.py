from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatasetMetricCurrencyPut")


@_attrs_define
class DatasetMetricCurrencyPut:
    """
    Attributes:
        symbol (str | Unset):
        symbol_position (str | Unset):
    """

    symbol: str | Unset = UNSET
    symbol_position: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        symbol = self.symbol

        symbol_position = self.symbol_position

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if symbol is not UNSET:
            field_dict["symbol"] = symbol
        if symbol_position is not UNSET:
            field_dict["symbolPosition"] = symbol_position

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        symbol = d.pop("symbol", UNSET)

        symbol_position = d.pop("symbolPosition", UNSET)

        dataset_metric_currency_put = cls(
            symbol=symbol,
            symbol_position=symbol_position,
        )

        dataset_metric_currency_put.additional_properties = d
        return dataset_metric_currency_put

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

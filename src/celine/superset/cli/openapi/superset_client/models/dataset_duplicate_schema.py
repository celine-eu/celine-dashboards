from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="DatasetDuplicateSchema")


@_attrs_define
class DatasetDuplicateSchema:
    """
    Attributes:
        base_model_id (int):
        table_name (str):
    """

    base_model_id: int
    table_name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base_model_id = self.base_model_id

        table_name = self.table_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "base_model_id": base_model_id,
                "table_name": table_name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        base_model_id = d.pop("base_model_id")

        table_name = d.pop("table_name")

        dataset_duplicate_schema = cls(
            base_model_id=base_model_id,
            table_name=table_name,
        )

        dataset_duplicate_schema.additional_properties = d
        return dataset_duplicate_schema

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

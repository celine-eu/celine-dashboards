from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatasetRelatedChart")


@_attrs_define
class DatasetRelatedChart:
    """
    Attributes:
        id (int | Unset):
        slice_name (str | Unset):
        viz_type (str | Unset):
    """

    id: int | Unset = UNSET
    slice_name: str | Unset = UNSET
    viz_type: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        slice_name = self.slice_name

        viz_type = self.viz_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if slice_name is not UNSET:
            field_dict["slice_name"] = slice_name
        if viz_type is not UNSET:
            field_dict["viz_type"] = viz_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        slice_name = d.pop("slice_name", UNSET)

        viz_type = d.pop("viz_type", UNSET)

        dataset_related_chart = cls(
            id=id,
            slice_name=slice_name,
            viz_type=viz_type,
        )

        dataset_related_chart.additional_properties = d
        return dataset_related_chart

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

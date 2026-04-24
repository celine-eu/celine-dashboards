from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PostApiV1DatasetGetOrCreateResponse200Result")


@_attrs_define
class PostApiV1DatasetGetOrCreateResponse200Result:
    """
    Attributes:
        table_id (int | Unset):
    """

    table_id: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        table_id = self.table_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if table_id is not UNSET:
            field_dict["table_id"] = table_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        table_id = d.pop("table_id", UNSET)

        post_api_v1_dataset_get_or_create_response_200_result = cls(
            table_id=table_id,
        )

        post_api_v1_dataset_get_or_create_response_200_result.additional_properties = d
        return post_api_v1_dataset_get_or_create_response_200_result

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

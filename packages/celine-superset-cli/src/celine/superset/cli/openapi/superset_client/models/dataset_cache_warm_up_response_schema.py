from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_cache_warm_up_response_single import DatasetCacheWarmUpResponseSingle


T = TypeVar("T", bound="DatasetCacheWarmUpResponseSchema")


@_attrs_define
class DatasetCacheWarmUpResponseSchema:
    """
    Attributes:
        result (list[DatasetCacheWarmUpResponseSingle] | Unset): A list of each chart's warmup status and errors if any
    """

    result: list[DatasetCacheWarmUpResponseSingle] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = []
            for result_item_data in self.result:
                result_item = result_item_data.to_dict()
                result.append(result_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset_cache_warm_up_response_single import DatasetCacheWarmUpResponseSingle

        d = dict(src_dict)
        _result = d.pop("result", UNSET)
        result: list[DatasetCacheWarmUpResponseSingle] | Unset = UNSET
        if _result is not UNSET:
            result = []
            for result_item_data in _result:
                result_item = DatasetCacheWarmUpResponseSingle.from_dict(result_item_data)

                result.append(result_item)

        dataset_cache_warm_up_response_schema = cls(
            result=result,
        )

        dataset_cache_warm_up_response_schema.additional_properties = d
        return dataset_cache_warm_up_response_schema

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

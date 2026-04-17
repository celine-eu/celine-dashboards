from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.distinct_result_response import DistinctResultResponse


T = TypeVar("T", bound="DistincResponseSchema")


@_attrs_define
class DistincResponseSchema:
    """
    Attributes:
        count (int | Unset): The total number of distinct values
        result (list[DistinctResultResponse] | Unset):
    """

    count: int | Unset = UNSET
    result: list[DistinctResultResponse] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        count = self.count

        result: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = []
            for result_item_data in self.result:
                result_item = result_item_data.to_dict()
                result.append(result_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if count is not UNSET:
            field_dict["count"] = count
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.distinct_result_response import DistinctResultResponse

        d = dict(src_dict)
        count = d.pop("count", UNSET)

        _result = d.pop("result", UNSET)
        result: list[DistinctResultResponse] | Unset = UNSET
        if _result is not UNSET:
            result = []
            for result_item_data in _result:
                result_item = DistinctResultResponse.from_dict(result_item_data)

                result.append(result_item)

        distinc_response_schema = cls(
            count=count,
            result=result,
        )

        distinc_response_schema.additional_properties = d
        return distinc_response_schema

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

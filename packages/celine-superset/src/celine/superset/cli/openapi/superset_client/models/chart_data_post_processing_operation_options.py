from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ChartDataPostProcessingOperationOptions")


@_attrs_define
class ChartDataPostProcessingOperationOptions:
    """Options specifying how to perform the operation. Please refer to the respective post processing operation option
    schemas. For example, `ChartDataPostProcessingOperationOptions` specifies the required options for the pivot
    operation.

        Example:
            {'aggregates': {'age_mean': {'column': 'age', 'operator': 'mean'}, 'age_q1': {'column': 'age', 'operator':
                'percentile', 'options': {'q': 0.25}}}, 'groupby': ['country', 'gender']}

    """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chart_data_post_processing_operation_options = cls()

        chart_data_post_processing_operation_options.additional_properties = d
        return chart_data_post_processing_operation_options

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

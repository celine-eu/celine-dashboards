from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_post_processing_operation_operation import (
    ChartDataPostProcessingOperationOperation,
    check_chart_data_post_processing_operation_operation,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_post_processing_operation_options import ChartDataPostProcessingOperationOptions


T = TypeVar("T", bound="ChartDataPostProcessingOperation")


@_attrs_define
class ChartDataPostProcessingOperation:
    """
    Attributes:
        operation (ChartDataPostProcessingOperationOperation): Post processing operation type Example: aggregate.
        options (ChartDataPostProcessingOperationOptions | Unset): Options specifying how to perform the operation.
            Please refer to the respective post processing operation option schemas. For example,
            `ChartDataPostProcessingOperationOptions` specifies the required options for the pivot operation. Example:
            {'aggregates': {'age_mean': {'column': 'age', 'operator': 'mean'}, 'age_q1': {'column': 'age', 'operator':
            'percentile', 'options': {'q': 0.25}}}, 'groupby': ['country', 'gender']}.
    """

    operation: ChartDataPostProcessingOperationOperation
    options: ChartDataPostProcessingOperationOptions | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        operation: str = self.operation

        options: dict[str, Any] | Unset = UNSET
        if not isinstance(self.options, Unset):
            options = self.options.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "operation": operation,
            }
        )
        if options is not UNSET:
            field_dict["options"] = options

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_post_processing_operation_options import ChartDataPostProcessingOperationOptions

        d = dict(src_dict)
        operation = check_chart_data_post_processing_operation_operation(d.pop("operation"))

        _options = d.pop("options", UNSET)
        options: ChartDataPostProcessingOperationOptions | Unset
        if isinstance(_options, Unset):
            options = UNSET
        else:
            options = ChartDataPostProcessingOperationOptions.from_dict(_options)

        chart_data_post_processing_operation = cls(
            operation=operation,
            options=options,
        )

        chart_data_post_processing_operation.additional_properties = d
        return chart_data_post_processing_operation

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

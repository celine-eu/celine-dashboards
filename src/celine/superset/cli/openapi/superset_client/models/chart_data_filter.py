from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_filter_op import ChartDataFilterOp, check_chart_data_filter_op
from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataFilter")


@_attrs_define
class ChartDataFilter:
    """
    Attributes:
        col (Any): The column to filter by. Can be either a string (physical or saved expression) or an object (adhoc
            column) Example: country.
        op (ChartDataFilterOp): The comparison operator. Example: IN.
        grain (str | Unset): Optional time grain for temporal filters Example: PT1M.
        is_extra (bool | Unset): Indicates if the filter has been added by a filter component as opposed to being a part
            of the original query.
        val (Any | Unset): The value or values to compare against. Can be a string, integer, decimal, None or list,
            depending on the operator. Example: ['China', 'France', 'Japan'].
    """

    col: Any
    op: ChartDataFilterOp
    grain: str | Unset = UNSET
    is_extra: bool | Unset = UNSET
    val: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        col = self.col

        op: str = self.op

        grain = self.grain

        is_extra = self.is_extra

        val = self.val

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "col": col,
                "op": op,
            }
        )
        if grain is not UNSET:
            field_dict["grain"] = grain
        if is_extra is not UNSET:
            field_dict["isExtra"] = is_extra
        if val is not UNSET:
            field_dict["val"] = val

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        col = d.pop("col")

        op = check_chart_data_filter_op(d.pop("op"))

        grain = d.pop("grain", UNSET)

        is_extra = d.pop("isExtra", UNSET)

        val = d.pop("val", UNSET)

        chart_data_filter = cls(
            col=col,
            op=op,
            grain=grain,
            is_extra=is_extra,
            val=val,
        )

        chart_data_filter.additional_properties = d
        return chart_data_filter

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

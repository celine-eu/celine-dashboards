from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportScheduleRestApiGetSlice")


@_attrs_define
class ReportScheduleRestApiGetSlice:
    """
    Attributes:
        id (int | Unset):
        slice_name (None | str | Unset):
        viz_type (None | str | Unset):
    """

    id: int | Unset = UNSET
    slice_name: None | str | Unset = UNSET
    viz_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        slice_name: None | str | Unset
        if isinstance(self.slice_name, Unset):
            slice_name = UNSET
        else:
            slice_name = self.slice_name

        viz_type: None | str | Unset
        if isinstance(self.viz_type, Unset):
            viz_type = UNSET
        else:
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

        def _parse_slice_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        slice_name = _parse_slice_name(d.pop("slice_name", UNSET))

        def _parse_viz_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        viz_type = _parse_viz_type(d.pop("viz_type", UNSET))

        report_schedule_rest_api_get_slice = cls(
            id=id,
            slice_name=slice_name,
            viz_type=viz_type,
        )

        report_schedule_rest_api_get_slice.additional_properties = d
        return report_schedule_rest_api_get_slice

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

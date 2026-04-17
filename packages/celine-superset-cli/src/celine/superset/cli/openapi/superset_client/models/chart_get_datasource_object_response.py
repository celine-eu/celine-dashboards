from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_get_datasource_object_data_response import ChartGetDatasourceObjectDataResponse


T = TypeVar("T", bound="ChartGetDatasourceObjectResponse")


@_attrs_define
class ChartGetDatasourceObjectResponse:
    """
    Attributes:
        label (str | Unset): The name of the datasource
        value (ChartGetDatasourceObjectDataResponse | Unset):
    """

    label: str | Unset = UNSET
    value: ChartGetDatasourceObjectDataResponse | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        label = self.label

        value: dict[str, Any] | Unset = UNSET
        if not isinstance(self.value, Unset):
            value = self.value.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if label is not UNSET:
            field_dict["label"] = label
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_get_datasource_object_data_response import ChartGetDatasourceObjectDataResponse

        d = dict(src_dict)
        label = d.pop("label", UNSET)

        _value = d.pop("value", UNSET)
        value: ChartGetDatasourceObjectDataResponse | Unset
        if isinstance(_value, Unset):
            value = UNSET
        else:
            value = ChartGetDatasourceObjectDataResponse.from_dict(_value)

        chart_get_datasource_object_response = cls(
            label=label,
            value=value,
        )

        chart_get_datasource_object_response.additional_properties = d
        return chart_get_datasource_object_response

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

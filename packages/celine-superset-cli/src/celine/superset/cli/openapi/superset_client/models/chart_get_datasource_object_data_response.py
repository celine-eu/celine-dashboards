from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartGetDatasourceObjectDataResponse")


@_attrs_define
class ChartGetDatasourceObjectDataResponse:
    """
    Attributes:
        datasource_id (int | Unset): The datasource identifier
        datasource_type (int | Unset): The datasource type
    """

    datasource_id: int | Unset = UNSET
    datasource_type: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        datasource_id = self.datasource_id

        datasource_type = self.datasource_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if datasource_id is not UNSET:
            field_dict["datasource_id"] = datasource_id
        if datasource_type is not UNSET:
            field_dict["datasource_type"] = datasource_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        datasource_id = d.pop("datasource_id", UNSET)

        datasource_type = d.pop("datasource_type", UNSET)

        chart_get_datasource_object_data_response = cls(
            datasource_id=datasource_id,
            datasource_type=datasource_type,
        )

        chart_get_datasource_object_data_response.additional_properties = d
        return chart_get_datasource_object_data_response

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

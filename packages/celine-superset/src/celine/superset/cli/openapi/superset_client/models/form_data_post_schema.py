from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.form_data_post_schema_datasource_type import (
    FormDataPostSchemaDatasourceType,
    check_form_data_post_schema_datasource_type,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="FormDataPostSchema")


@_attrs_define
class FormDataPostSchema:
    """
    Attributes:
        datasource_id (int): The datasource ID
        datasource_type (FormDataPostSchemaDatasourceType): The datasource type
        form_data (str): Any type of JSON supported text.
        chart_id (int | Unset): The chart ID
    """

    datasource_id: int
    datasource_type: FormDataPostSchemaDatasourceType
    form_data: str
    chart_id: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        datasource_id = self.datasource_id

        datasource_type: str = self.datasource_type

        form_data = self.form_data

        chart_id = self.chart_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "datasource_id": datasource_id,
                "datasource_type": datasource_type,
                "form_data": form_data,
            }
        )
        if chart_id is not UNSET:
            field_dict["chart_id"] = chart_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        datasource_id = d.pop("datasource_id")

        datasource_type = check_form_data_post_schema_datasource_type(d.pop("datasource_type"))

        form_data = d.pop("form_data")

        chart_id = d.pop("chart_id", UNSET)

        form_data_post_schema = cls(
            datasource_id=datasource_id,
            datasource_type=datasource_type,
            form_data=form_data,
            chart_id=chart_id,
        )

        form_data_post_schema.additional_properties = d
        return form_data_post_schema

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

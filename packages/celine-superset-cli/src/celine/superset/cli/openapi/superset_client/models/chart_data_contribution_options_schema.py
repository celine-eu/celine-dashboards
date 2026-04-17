from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_contribution_options_schema_orientation import (
    ChartDataContributionOptionsSchemaOrientation,
    check_chart_data_contribution_options_schema_orientation,
)

T = TypeVar("T", bound="ChartDataContributionOptionsSchema")


@_attrs_define
class ChartDataContributionOptionsSchema:
    """
    Attributes:
        orientation (ChartDataContributionOptionsSchemaOrientation): Should cell values be calculated across the row or
            column. Example: row.
    """

    orientation: ChartDataContributionOptionsSchemaOrientation
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        orientation: str = self.orientation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "orientation": orientation,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        orientation = check_chart_data_contribution_options_schema_orientation(d.pop("orientation"))

        chart_data_contribution_options_schema = cls(
            orientation=orientation,
        )

        chart_data_contribution_options_schema.additional_properties = d
        return chart_data_contribution_options_schema

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

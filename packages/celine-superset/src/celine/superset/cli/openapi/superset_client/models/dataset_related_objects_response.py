from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_related_charts import DatasetRelatedCharts
    from ..models.dataset_related_dashboards import DatasetRelatedDashboards


T = TypeVar("T", bound="DatasetRelatedObjectsResponse")


@_attrs_define
class DatasetRelatedObjectsResponse:
    """
    Attributes:
        charts (DatasetRelatedCharts | Unset):
        dashboards (DatasetRelatedDashboards | Unset):
    """

    charts: DatasetRelatedCharts | Unset = UNSET
    dashboards: DatasetRelatedDashboards | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        charts: dict[str, Any] | Unset = UNSET
        if not isinstance(self.charts, Unset):
            charts = self.charts.to_dict()

        dashboards: dict[str, Any] | Unset = UNSET
        if not isinstance(self.dashboards, Unset):
            dashboards = self.dashboards.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if charts is not UNSET:
            field_dict["charts"] = charts
        if dashboards is not UNSET:
            field_dict["dashboards"] = dashboards

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset_related_charts import DatasetRelatedCharts
        from ..models.dataset_related_dashboards import DatasetRelatedDashboards

        d = dict(src_dict)
        _charts = d.pop("charts", UNSET)
        charts: DatasetRelatedCharts | Unset
        if isinstance(_charts, Unset):
            charts = UNSET
        else:
            charts = DatasetRelatedCharts.from_dict(_charts)

        _dashboards = d.pop("dashboards", UNSET)
        dashboards: DatasetRelatedDashboards | Unset
        if isinstance(_dashboards, Unset):
            dashboards = UNSET
        else:
            dashboards = DatasetRelatedDashboards.from_dict(_dashboards)

        dataset_related_objects_response = cls(
            charts=charts,
            dashboards=dashboards,
        )

        dataset_related_objects_response.additional_properties = d
        return dataset_related_objects_response

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

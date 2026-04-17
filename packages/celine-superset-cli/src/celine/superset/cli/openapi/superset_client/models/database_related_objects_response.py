from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.database_related_charts import DatabaseRelatedCharts
    from ..models.database_related_dashboards import DatabaseRelatedDashboards


T = TypeVar("T", bound="DatabaseRelatedObjectsResponse")


@_attrs_define
class DatabaseRelatedObjectsResponse:
    """
    Attributes:
        charts (DatabaseRelatedCharts | Unset):
        dashboards (DatabaseRelatedDashboards | Unset):
    """

    charts: DatabaseRelatedCharts | Unset = UNSET
    dashboards: DatabaseRelatedDashboards | Unset = UNSET
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
        from ..models.database_related_charts import DatabaseRelatedCharts
        from ..models.database_related_dashboards import DatabaseRelatedDashboards

        d = dict(src_dict)
        _charts = d.pop("charts", UNSET)
        charts: DatabaseRelatedCharts | Unset
        if isinstance(_charts, Unset):
            charts = UNSET
        else:
            charts = DatabaseRelatedCharts.from_dict(_charts)

        _dashboards = d.pop("dashboards", UNSET)
        dashboards: DatabaseRelatedDashboards | Unset
        if isinstance(_dashboards, Unset):
            dashboards = UNSET
        else:
            dashboards = DatabaseRelatedDashboards.from_dict(_dashboards)

        database_related_objects_response = cls(
            charts=charts,
            dashboards=dashboards,
        )

        database_related_objects_response.additional_properties = d
        return database_related_objects_response

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

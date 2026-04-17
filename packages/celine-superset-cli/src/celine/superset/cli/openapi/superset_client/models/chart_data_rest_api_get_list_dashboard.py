from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataRestApiGetListDashboard")


@_attrs_define
class ChartDataRestApiGetListDashboard:
    """
    Attributes:
        dashboard_title (None | str | Unset):
        id (int | Unset):
    """

    dashboard_title: None | str | Unset = UNSET
    id: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dashboard_title: None | str | Unset
        if isinstance(self.dashboard_title, Unset):
            dashboard_title = UNSET
        else:
            dashboard_title = self.dashboard_title

        id = self.id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if dashboard_title is not UNSET:
            field_dict["dashboard_title"] = dashboard_title
        if id is not UNSET:
            field_dict["id"] = id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_dashboard_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dashboard_title = _parse_dashboard_title(d.pop("dashboard_title", UNSET))

        id = d.pop("id", UNSET)

        chart_data_rest_api_get_list_dashboard = cls(
            dashboard_title=dashboard_title,
            id=id,
        )

        chart_data_rest_api_get_list_dashboard.additional_properties = d
        return chart_data_rest_api_get_list_dashboard

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

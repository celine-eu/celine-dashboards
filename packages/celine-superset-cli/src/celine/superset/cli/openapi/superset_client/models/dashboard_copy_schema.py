from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DashboardCopySchema")


@_attrs_define
class DashboardCopySchema:
    """
    Attributes:
        json_metadata (str): This JSON object is generated dynamically when clicking the save or overwrite button in the
            dashboard view. It is exposed here for reference and for power users who may want to alter  specific parameters.
        css (str | Unset): Override CSS for the dashboard.
        dashboard_title (None | str | Unset): A title for the dashboard.
        duplicate_slices (bool | Unset): Whether or not to also copy all charts on the dashboard
    """

    json_metadata: str
    css: str | Unset = UNSET
    dashboard_title: None | str | Unset = UNSET
    duplicate_slices: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        json_metadata = self.json_metadata

        css = self.css

        dashboard_title: None | str | Unset
        if isinstance(self.dashboard_title, Unset):
            dashboard_title = UNSET
        else:
            dashboard_title = self.dashboard_title

        duplicate_slices = self.duplicate_slices

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "json_metadata": json_metadata,
            }
        )
        if css is not UNSET:
            field_dict["css"] = css
        if dashboard_title is not UNSET:
            field_dict["dashboard_title"] = dashboard_title
        if duplicate_slices is not UNSET:
            field_dict["duplicate_slices"] = duplicate_slices

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        json_metadata = d.pop("json_metadata")

        css = d.pop("css", UNSET)

        def _parse_dashboard_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dashboard_title = _parse_dashboard_title(d.pop("dashboard_title", UNSET))

        duplicate_slices = d.pop("duplicate_slices", UNSET)

        dashboard_copy_schema = cls(
            json_metadata=json_metadata,
            css=css,
            dashboard_title=dashboard_title,
            duplicate_slices=duplicate_slices,
        )

        dashboard_copy_schema.additional_properties = d
        return dashboard_copy_schema

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

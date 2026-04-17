from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dashboard_permalink_state_schema_data_mask_type_0 import DashboardPermalinkStateSchemaDataMaskType0


T = TypeVar("T", bound="DashboardPermalinkStateSchema")


@_attrs_define
class DashboardPermalinkStateSchema:
    """
    Attributes:
        active_tabs (list[str] | None | Unset): Current active dashboard tabs
        anchor (None | str | Unset): Optional anchor link added to url hash
        data_mask (DashboardPermalinkStateSchemaDataMaskType0 | None | Unset): Data mask used for native filter state
        url_params (list[Any] | None | Unset): URL Parameters
    """

    active_tabs: list[str] | None | Unset = UNSET
    anchor: None | str | Unset = UNSET
    data_mask: DashboardPermalinkStateSchemaDataMaskType0 | None | Unset = UNSET
    url_params: list[Any] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.dashboard_permalink_state_schema_data_mask_type_0 import (
            DashboardPermalinkStateSchemaDataMaskType0,
        )

        active_tabs: list[str] | None | Unset
        if isinstance(self.active_tabs, Unset):
            active_tabs = UNSET
        elif isinstance(self.active_tabs, list):
            active_tabs = self.active_tabs

        else:
            active_tabs = self.active_tabs

        anchor: None | str | Unset
        if isinstance(self.anchor, Unset):
            anchor = UNSET
        else:
            anchor = self.anchor

        data_mask: dict[str, Any] | None | Unset
        if isinstance(self.data_mask, Unset):
            data_mask = UNSET
        elif isinstance(self.data_mask, DashboardPermalinkStateSchemaDataMaskType0):
            data_mask = self.data_mask.to_dict()
        else:
            data_mask = self.data_mask

        url_params: list[Any] | None | Unset
        if isinstance(self.url_params, Unset):
            url_params = UNSET
        elif isinstance(self.url_params, list):
            url_params = self.url_params

        else:
            url_params = self.url_params

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if active_tabs is not UNSET:
            field_dict["activeTabs"] = active_tabs
        if anchor is not UNSET:
            field_dict["anchor"] = anchor
        if data_mask is not UNSET:
            field_dict["dataMask"] = data_mask
        if url_params is not UNSET:
            field_dict["urlParams"] = url_params

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard_permalink_state_schema_data_mask_type_0 import (
            DashboardPermalinkStateSchemaDataMaskType0,
        )

        d = dict(src_dict)

        def _parse_active_tabs(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                active_tabs_type_0 = cast(list[str], data)

                return active_tabs_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        active_tabs = _parse_active_tabs(d.pop("activeTabs", UNSET))

        def _parse_anchor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        anchor = _parse_anchor(d.pop("anchor", UNSET))

        def _parse_data_mask(data: object) -> DashboardPermalinkStateSchemaDataMaskType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                data_mask_type_0 = DashboardPermalinkStateSchemaDataMaskType0.from_dict(data)

                return data_mask_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DashboardPermalinkStateSchemaDataMaskType0 | None | Unset, data)

        data_mask = _parse_data_mask(d.pop("dataMask", UNSET))

        def _parse_url_params(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                url_params_type_0 = cast(list[Any], data)

                return url_params_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        url_params = _parse_url_params(d.pop("urlParams", UNSET))

        dashboard_permalink_state_schema = cls(
            active_tabs=active_tabs,
            anchor=anchor,
            data_mask=data_mask,
            url_params=url_params,
        )

        dashboard_permalink_state_schema.additional_properties = d
        return dashboard_permalink_state_schema

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

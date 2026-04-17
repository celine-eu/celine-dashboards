from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.dashboard_rest_api_get_list_tag_type import (
    DashboardRestApiGetListTagType,
    check_dashboard_rest_api_get_list_tag_type,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="DashboardRestApiGetListTag")


@_attrs_define
class DashboardRestApiGetListTag:
    """
    Attributes:
        id (int | Unset):
        name (None | str | Unset):
        type_ (DashboardRestApiGetListTagType | Unset):
    """

    id: int | Unset = UNSET
    name: None | str | Unset = UNSET
    type_: DashboardRestApiGetListTagType | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        type_: int | Unset = UNSET
        if not isinstance(self.type_, Unset):
            type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        _type_ = d.pop("type", UNSET)
        type_: DashboardRestApiGetListTagType | Unset
        if isinstance(_type_, Unset):
            type_ = UNSET
        else:
            type_ = check_dashboard_rest_api_get_list_tag_type(_type_)

        dashboard_rest_api_get_list_tag = cls(
            id=id,
            name=name,
            type_=type_,
        )

        dashboard_rest_api_get_list_tag.additional_properties = d
        return dashboard_rest_api_get_list_tag

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

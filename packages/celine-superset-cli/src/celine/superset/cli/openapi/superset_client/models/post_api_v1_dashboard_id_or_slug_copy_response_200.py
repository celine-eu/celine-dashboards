from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PostApiV1DashboardIdOrSlugCopyResponse200")


@_attrs_define
class PostApiV1DashboardIdOrSlugCopyResponse200:
    """
    Attributes:
        id (float | Unset):
        last_modified_time (float | Unset):
    """

    id: float | Unset = UNSET
    last_modified_time: float | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        last_modified_time = self.last_modified_time

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if last_modified_time is not UNSET:
            field_dict["last_modified_time"] = last_modified_time

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        last_modified_time = d.pop("last_modified_time", UNSET)

        post_api_v1_dashboard_id_or_slug_copy_response_200 = cls(
            id=id,
            last_modified_time=last_modified_time,
        )

        post_api_v1_dashboard_id_or_slug_copy_response_200.additional_properties = d
        return post_api_v1_dashboard_id_or_slug_copy_response_200

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

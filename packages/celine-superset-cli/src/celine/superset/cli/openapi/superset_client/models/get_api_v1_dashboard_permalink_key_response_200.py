from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_dashboard_permalink_key_response_200_state import (
        GetApiV1DashboardPermalinkKeyResponse200State,
    )


T = TypeVar("T", bound="GetApiV1DashboardPermalinkKeyResponse200")


@_attrs_define
class GetApiV1DashboardPermalinkKeyResponse200:
    """
    Attributes:
        state (GetApiV1DashboardPermalinkKeyResponse200State | Unset): The stored state
    """

    state: GetApiV1DashboardPermalinkKeyResponse200State | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        state: dict[str, Any] | Unset = UNSET
        if not isinstance(self.state, Unset):
            state = self.state.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if state is not UNSET:
            field_dict["state"] = state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_dashboard_permalink_key_response_200_state import (
            GetApiV1DashboardPermalinkKeyResponse200State,
        )

        d = dict(src_dict)
        _state = d.pop("state", UNSET)
        state: GetApiV1DashboardPermalinkKeyResponse200State | Unset
        if isinstance(_state, Unset):
            state = UNSET
        else:
            state = GetApiV1DashboardPermalinkKeyResponse200State.from_dict(_state)

        get_api_v1_dashboard_permalink_key_response_200 = cls(
            state=state,
        )

        get_api_v1_dashboard_permalink_key_response_200.additional_properties = d
        return get_api_v1_dashboard_permalink_key_response_200

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

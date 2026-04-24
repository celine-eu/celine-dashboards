from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.embedded_dashboard_response_schema import EmbeddedDashboardResponseSchema


T = TypeVar("T", bound="PostApiV1DashboardIdOrSlugEmbeddedResponse200")


@_attrs_define
class PostApiV1DashboardIdOrSlugEmbeddedResponse200:
    """
    Attributes:
        result (EmbeddedDashboardResponseSchema | Unset):
    """

    result: EmbeddedDashboardResponseSchema | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = self.result.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.embedded_dashboard_response_schema import EmbeddedDashboardResponseSchema

        d = dict(src_dict)
        _result = d.pop("result", UNSET)
        result: EmbeddedDashboardResponseSchema | Unset
        if isinstance(_result, Unset):
            result = UNSET
        else:
            result = EmbeddedDashboardResponseSchema.from_dict(_result)

        post_api_v1_dashboard_id_or_slug_embedded_response_200 = cls(
            result=result,
        )

        post_api_v1_dashboard_id_or_slug_embedded_response_200.additional_properties = d
        return post_api_v1_dashboard_id_or_slug_embedded_response_200

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

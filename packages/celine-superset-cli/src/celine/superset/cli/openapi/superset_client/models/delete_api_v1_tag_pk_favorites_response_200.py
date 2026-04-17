from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.delete_api_v1_tag_pk_favorites_response_200_result import DeleteApiV1TagPkFavoritesResponse200Result


T = TypeVar("T", bound="DeleteApiV1TagPkFavoritesResponse200")


@_attrs_define
class DeleteApiV1TagPkFavoritesResponse200:
    """
    Attributes:
        result (DeleteApiV1TagPkFavoritesResponse200Result | Unset):
    """

    result: DeleteApiV1TagPkFavoritesResponse200Result | Unset = UNSET
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
        from ..models.delete_api_v1_tag_pk_favorites_response_200_result import (
            DeleteApiV1TagPkFavoritesResponse200Result,
        )

        d = dict(src_dict)
        _result = d.pop("result", UNSET)
        result: DeleteApiV1TagPkFavoritesResponse200Result | Unset
        if isinstance(_result, Unset):
            result = UNSET
        else:
            result = DeleteApiV1TagPkFavoritesResponse200Result.from_dict(_result)

        delete_api_v1_tag_pk_favorites_response_200 = cls(
            result=result,
        )

        delete_api_v1_tag_pk_favorites_response_200.additional_properties = d
        return delete_api_v1_tag_pk_favorites_response_200

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

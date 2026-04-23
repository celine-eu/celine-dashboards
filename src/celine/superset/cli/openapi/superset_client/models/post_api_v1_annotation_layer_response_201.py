from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.annotation_layer_rest_api_post import AnnotationLayerRestApiPost


T = TypeVar("T", bound="PostApiV1AnnotationLayerResponse201")


@_attrs_define
class PostApiV1AnnotationLayerResponse201:
    """
    Attributes:
        id (float | Unset):
        result (AnnotationLayerRestApiPost | Unset):
    """

    id: float | Unset = UNSET
    result: AnnotationLayerRestApiPost | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        result: dict[str, Any] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = self.result.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.annotation_layer_rest_api_post import AnnotationLayerRestApiPost

        d = dict(src_dict)
        id = d.pop("id", UNSET)

        _result = d.pop("result", UNSET)
        result: AnnotationLayerRestApiPost | Unset
        if isinstance(_result, Unset):
            result = UNSET
        else:
            result = AnnotationLayerRestApiPost.from_dict(_result)

        post_api_v1_annotation_layer_response_201 = cls(
            id=id,
            result=result,
        )

        post_api_v1_annotation_layer_response_201.additional_properties = d
        return post_api_v1_annotation_layer_response_201

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

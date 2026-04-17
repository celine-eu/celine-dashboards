from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TagRestApiPost")


@_attrs_define
class TagRestApiPost:
    """
    Attributes:
        description (None | str | Unset):
        name (str | Unset):
        objects_to_tag (list[Any] | Unset): Objects to tag
    """

    description: None | str | Unset = UNSET
    name: str | Unset = UNSET
    objects_to_tag: list[Any] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        name = self.name

        objects_to_tag: list[Any] | Unset = UNSET
        if not isinstance(self.objects_to_tag, Unset):
            objects_to_tag = self.objects_to_tag

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if name is not UNSET:
            field_dict["name"] = name
        if objects_to_tag is not UNSET:
            field_dict["objects_to_tag"] = objects_to_tag

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        name = d.pop("name", UNSET)

        objects_to_tag = cast(list[Any], d.pop("objects_to_tag", UNSET))

        tag_rest_api_post = cls(
            description=description,
            name=name,
            objects_to_tag=objects_to_tag,
        )

        tag_rest_api_post.additional_properties = d
        return tag_rest_api_post

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

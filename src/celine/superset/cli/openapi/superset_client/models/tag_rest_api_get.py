from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.tag_rest_api_get_type import TagRestApiGetType, check_tag_rest_api_get_type
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.tag_rest_api_get_user import TagRestApiGetUser
    from ..models.tag_rest_api_get_user_1 import TagRestApiGetUser1


T = TypeVar("T", bound="TagRestApiGet")


@_attrs_define
class TagRestApiGet:
    """
    Attributes:
        changed_by (TagRestApiGetUser | Unset):
        changed_on_delta_humanized (Any | Unset):
        created_by (TagRestApiGetUser1 | Unset):
        created_on_delta_humanized (Any | Unset):
        description (None | str | Unset):
        id (int | Unset):
        name (None | str | Unset):
        type_ (TagRestApiGetType | Unset):
    """

    changed_by: TagRestApiGetUser | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    created_by: TagRestApiGetUser1 | Unset = UNSET
    created_on_delta_humanized: Any | Unset = UNSET
    description: None | str | Unset = UNSET
    id: int | Unset = UNSET
    name: None | str | Unset = UNSET
    type_: TagRestApiGetType | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on_delta_humanized = self.changed_on_delta_humanized

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on_delta_humanized = self.created_on_delta_humanized

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

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
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on_delta_humanized is not UNSET:
            field_dict["created_on_delta_humanized"] = created_on_delta_humanized
        if description is not UNSET:
            field_dict["description"] = description
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.tag_rest_api_get_user import TagRestApiGetUser
        from ..models.tag_rest_api_get_user_1 import TagRestApiGetUser1

        d = dict(src_dict)
        _changed_by = d.pop("changed_by", UNSET)
        changed_by: TagRestApiGetUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = TagRestApiGetUser.from_dict(_changed_by)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: TagRestApiGetUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = TagRestApiGetUser1.from_dict(_created_by)

        created_on_delta_humanized = d.pop("created_on_delta_humanized", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        id = d.pop("id", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        _type_ = d.pop("type", UNSET)
        type_: TagRestApiGetType | Unset
        if isinstance(_type_, Unset):
            type_ = UNSET
        else:
            type_ = check_tag_rest_api_get_type(_type_)

        tag_rest_api_get = cls(
            changed_by=changed_by,
            changed_on_delta_humanized=changed_on_delta_humanized,
            created_by=created_by,
            created_on_delta_humanized=created_on_delta_humanized,
            description=description,
            id=id,
            name=name,
            type_=type_,
        )

        tag_rest_api_get.additional_properties = d
        return tag_rest_api_get

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

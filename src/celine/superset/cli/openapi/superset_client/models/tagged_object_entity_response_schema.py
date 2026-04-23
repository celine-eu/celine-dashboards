from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.tag_get_response_schema import TagGetResponseSchema
    from ..models.user_1 import User1
    from ..models.user_2 import User2


T = TypeVar("T", bound="TaggedObjectEntityResponseSchema")


@_attrs_define
class TaggedObjectEntityResponseSchema:
    """
    Attributes:
        changed_on (datetime.datetime | Unset):
        created_by (User1 | Unset):
        creator (str | Unset):
        id (int | Unset):
        name (str | Unset):
        owners (list[User2] | Unset):
        tags (list[TagGetResponseSchema] | Unset):
        type_ (str | Unset):
        url (str | Unset):
    """

    changed_on: datetime.datetime | Unset = UNSET
    created_by: User1 | Unset = UNSET
    creator: str | Unset = UNSET
    id: int | Unset = UNSET
    name: str | Unset = UNSET
    owners: list[User2] | Unset = UNSET
    tags: list[TagGetResponseSchema] | Unset = UNSET
    type_: str | Unset = UNSET
    url: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        changed_on: str | Unset = UNSET
        if not isinstance(self.changed_on, Unset):
            changed_on = self.changed_on.isoformat()

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        creator = self.creator

        id = self.id

        name = self.name

        owners: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = []
            for owners_item_data in self.owners:
                owners_item = owners_item_data.to_dict()
                owners.append(owners_item)

        tags: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = []
            for tags_item_data in self.tags:
                tags_item = tags_item_data.to_dict()
                tags.append(tags_item)

        type_ = self.type_

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if creator is not UNSET:
            field_dict["creator"] = creator
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if owners is not UNSET:
            field_dict["owners"] = owners
        if tags is not UNSET:
            field_dict["tags"] = tags
        if type_ is not UNSET:
            field_dict["type"] = type_
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.tag_get_response_schema import TagGetResponseSchema
        from ..models.user_1 import User1
        from ..models.user_2 import User2

        d = dict(src_dict)
        _changed_on = d.pop("changed_on", UNSET)
        changed_on: datetime.datetime | Unset
        if isinstance(_changed_on, Unset):
            changed_on = UNSET
        else:
            changed_on = isoparse(_changed_on)

        _created_by = d.pop("created_by", UNSET)
        created_by: User1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = User1.from_dict(_created_by)

        creator = d.pop("creator", UNSET)

        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        _owners = d.pop("owners", UNSET)
        owners: list[User2] | Unset = UNSET
        if _owners is not UNSET:
            owners = []
            for owners_item_data in _owners:
                owners_item = User2.from_dict(owners_item_data)

                owners.append(owners_item)

        _tags = d.pop("tags", UNSET)
        tags: list[TagGetResponseSchema] | Unset = UNSET
        if _tags is not UNSET:
            tags = []
            for tags_item_data in _tags:
                tags_item = TagGetResponseSchema.from_dict(tags_item_data)

                tags.append(tags_item)

        type_ = d.pop("type", UNSET)

        url = d.pop("url", UNSET)

        tagged_object_entity_response_schema = cls(
            changed_on=changed_on,
            created_by=created_by,
            creator=creator,
            id=id,
            name=name,
            owners=owners,
            tags=tags,
            type_=type_,
            url=url,
        )

        tagged_object_entity_response_schema.additional_properties = d
        return tagged_object_entity_response_schema

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

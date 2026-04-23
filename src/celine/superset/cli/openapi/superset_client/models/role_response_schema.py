from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RoleResponseSchema")


@_attrs_define
class RoleResponseSchema:
    """
    Attributes:
        id (int | Unset):
        name (str | Unset):
        permission_ids (list[int] | Unset):
        user_ids (list[int] | Unset):
    """

    id: int | Unset = UNSET
    name: str | Unset = UNSET
    permission_ids: list[int] | Unset = UNSET
    user_ids: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        permission_ids: list[int] | Unset = UNSET
        if not isinstance(self.permission_ids, Unset):
            permission_ids = self.permission_ids

        user_ids: list[int] | Unset = UNSET
        if not isinstance(self.user_ids, Unset):
            user_ids = self.user_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if permission_ids is not UNSET:
            field_dict["permission_ids"] = permission_ids
        if user_ids is not UNSET:
            field_dict["user_ids"] = user_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        permission_ids = cast(list[int], d.pop("permission_ids", UNSET))

        user_ids = cast(list[int], d.pop("user_ids", UNSET))

        role_response_schema = cls(
            id=id,
            name=name,
            permission_ids=permission_ids,
            user_ids=user_ids,
        )

        role_response_schema.additional_properties = d
        return role_response_schema

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

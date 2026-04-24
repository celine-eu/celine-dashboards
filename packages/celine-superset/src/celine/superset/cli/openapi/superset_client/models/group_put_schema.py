from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GroupPutSchema")


@_attrs_define
class GroupPutSchema:
    """
    Attributes:
        description (None | str | Unset): Group description
        label (None | str | Unset): Group label
        name (str | Unset): Group name
        roles (list[int] | Unset): Group roles
        users (list[int] | Unset): Group users
    """

    description: None | str | Unset = UNSET
    label: None | str | Unset = UNSET
    name: str | Unset = UNSET
    roles: list[int] | Unset = UNSET
    users: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        label: None | str | Unset
        if isinstance(self.label, Unset):
            label = UNSET
        else:
            label = self.label

        name = self.name

        roles: list[int] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles

        users: list[int] | Unset = UNSET
        if not isinstance(self.users, Unset):
            users = self.users

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if label is not UNSET:
            field_dict["label"] = label
        if name is not UNSET:
            field_dict["name"] = name
        if roles is not UNSET:
            field_dict["roles"] = roles
        if users is not UNSET:
            field_dict["users"] = users

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

        def _parse_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        label = _parse_label(d.pop("label", UNSET))

        name = d.pop("name", UNSET)

        roles = cast(list[int], d.pop("roles", UNSET))

        users = cast(list[int], d.pop("users", UNSET))

        group_put_schema = cls(
            description=description,
            label=label,
            name=name,
            roles=roles,
            users=users,
        )

        group_put_schema.additional_properties = d
        return group_put_schema

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

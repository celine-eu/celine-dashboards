from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.group_api_get_role import GroupApiGetRole
    from ..models.group_api_get_user import GroupApiGetUser


T = TypeVar("T", bound="GroupApiGet")


@_attrs_define
class GroupApiGet:
    """
    Attributes:
        name (str):
        description (None | str | Unset):
        id (int | Unset):
        label (None | str | Unset):
        roles (GroupApiGetRole | Unset):
        users (GroupApiGetUser | Unset):
    """

    name: str
    description: None | str | Unset = UNSET
    id: int | Unset = UNSET
    label: None | str | Unset = UNSET
    roles: GroupApiGetRole | Unset = UNSET
    users: GroupApiGetUser | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        id = self.id

        label: None | str | Unset
        if isinstance(self.label, Unset):
            label = UNSET
        else:
            label = self.label

        roles: dict[str, Any] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles.to_dict()

        users: dict[str, Any] | Unset = UNSET
        if not isinstance(self.users, Unset):
            users = self.users.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if id is not UNSET:
            field_dict["id"] = id
        if label is not UNSET:
            field_dict["label"] = label
        if roles is not UNSET:
            field_dict["roles"] = roles
        if users is not UNSET:
            field_dict["users"] = users

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.group_api_get_role import GroupApiGetRole
        from ..models.group_api_get_user import GroupApiGetUser

        d = dict(src_dict)
        name = d.pop("name")

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        id = d.pop("id", UNSET)

        def _parse_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        label = _parse_label(d.pop("label", UNSET))

        _roles = d.pop("roles", UNSET)
        roles: GroupApiGetRole | Unset
        if isinstance(_roles, Unset):
            roles = UNSET
        else:
            roles = GroupApiGetRole.from_dict(_roles)

        _users = d.pop("users", UNSET)
        users: GroupApiGetUser | Unset
        if isinstance(_users, Unset):
            users = UNSET
        else:
            users = GroupApiGetUser.from_dict(_users)

        group_api_get = cls(
            name=name,
            description=description,
            id=id,
            label=label,
            roles=roles,
            users=users,
        )

        group_api_get.additional_properties = d
        return group_api_get

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

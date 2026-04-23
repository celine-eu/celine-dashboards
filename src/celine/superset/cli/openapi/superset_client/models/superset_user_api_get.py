from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.superset_user_api_get_group import SupersetUserApiGetGroup
    from ..models.superset_user_api_get_role import SupersetUserApiGetRole
    from ..models.superset_user_api_get_user import SupersetUserApiGetUser
    from ..models.superset_user_api_get_user_1 import SupersetUserApiGetUser1


T = TypeVar("T", bound="SupersetUserApiGet")


@_attrs_define
class SupersetUserApiGet:
    """
    Attributes:
        email (str):
        first_name (str):
        last_name (str):
        username (str):
        active (bool | None | Unset):
        changed_by (SupersetUserApiGetUser1 | Unset):
        changed_on (datetime.datetime | None | Unset):
        created_by (SupersetUserApiGetUser | Unset):
        created_on (datetime.datetime | None | Unset):
        fail_login_count (int | None | Unset):
        groups (SupersetUserApiGetGroup | Unset):
        id (int | Unset):
        last_login (datetime.datetime | None | Unset):
        login_count (int | None | Unset):
        roles (SupersetUserApiGetRole | Unset):
    """

    email: str
    first_name: str
    last_name: str
    username: str
    active: bool | None | Unset = UNSET
    changed_by: SupersetUserApiGetUser1 | Unset = UNSET
    changed_on: datetime.datetime | None | Unset = UNSET
    created_by: SupersetUserApiGetUser | Unset = UNSET
    created_on: datetime.datetime | None | Unset = UNSET
    fail_login_count: int | None | Unset = UNSET
    groups: SupersetUserApiGetGroup | Unset = UNSET
    id: int | Unset = UNSET
    last_login: datetime.datetime | None | Unset = UNSET
    login_count: int | None | Unset = UNSET
    roles: SupersetUserApiGetRole | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        first_name = self.first_name

        last_name = self.last_name

        username = self.username

        active: bool | None | Unset
        if isinstance(self.active, Unset):
            active = UNSET
        else:
            active = self.active

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on: None | str | Unset
        if isinstance(self.created_on, Unset):
            created_on = UNSET
        elif isinstance(self.created_on, datetime.datetime):
            created_on = self.created_on.isoformat()
        else:
            created_on = self.created_on

        fail_login_count: int | None | Unset
        if isinstance(self.fail_login_count, Unset):
            fail_login_count = UNSET
        else:
            fail_login_count = self.fail_login_count

        groups: dict[str, Any] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups.to_dict()

        id = self.id

        last_login: None | str | Unset
        if isinstance(self.last_login, Unset):
            last_login = UNSET
        elif isinstance(self.last_login, datetime.datetime):
            last_login = self.last_login.isoformat()
        else:
            last_login = self.last_login

        login_count: int | None | Unset
        if isinstance(self.login_count, Unset):
            login_count = UNSET
        else:
            login_count = self.login_count

        roles: dict[str, Any] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "username": username,
            }
        )
        if active is not UNSET:
            field_dict["active"] = active
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on is not UNSET:
            field_dict["created_on"] = created_on
        if fail_login_count is not UNSET:
            field_dict["fail_login_count"] = fail_login_count
        if groups is not UNSET:
            field_dict["groups"] = groups
        if id is not UNSET:
            field_dict["id"] = id
        if last_login is not UNSET:
            field_dict["last_login"] = last_login
        if login_count is not UNSET:
            field_dict["login_count"] = login_count
        if roles is not UNSET:
            field_dict["roles"] = roles

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.superset_user_api_get_group import SupersetUserApiGetGroup
        from ..models.superset_user_api_get_role import SupersetUserApiGetRole
        from ..models.superset_user_api_get_user import SupersetUserApiGetUser
        from ..models.superset_user_api_get_user_1 import SupersetUserApiGetUser1

        d = dict(src_dict)
        email = d.pop("email")

        first_name = d.pop("first_name")

        last_name = d.pop("last_name")

        username = d.pop("username")

        def _parse_active(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        active = _parse_active(d.pop("active", UNSET))

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: SupersetUserApiGetUser1 | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = SupersetUserApiGetUser1.from_dict(_changed_by)

        def _parse_changed_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                changed_on_type_0 = isoparse(data)

                return changed_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        changed_on = _parse_changed_on(d.pop("changed_on", UNSET))

        _created_by = d.pop("created_by", UNSET)
        created_by: SupersetUserApiGetUser | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = SupersetUserApiGetUser.from_dict(_created_by)

        def _parse_created_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                created_on_type_0 = isoparse(data)

                return created_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        created_on = _parse_created_on(d.pop("created_on", UNSET))

        def _parse_fail_login_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        fail_login_count = _parse_fail_login_count(d.pop("fail_login_count", UNSET))

        _groups = d.pop("groups", UNSET)
        groups: SupersetUserApiGetGroup | Unset
        if isinstance(_groups, Unset):
            groups = UNSET
        else:
            groups = SupersetUserApiGetGroup.from_dict(_groups)

        id = d.pop("id", UNSET)

        def _parse_last_login(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_login_type_0 = isoparse(data)

                return last_login_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_login = _parse_last_login(d.pop("last_login", UNSET))

        def _parse_login_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        login_count = _parse_login_count(d.pop("login_count", UNSET))

        _roles = d.pop("roles", UNSET)
        roles: SupersetUserApiGetRole | Unset
        if isinstance(_roles, Unset):
            roles = UNSET
        else:
            roles = SupersetUserApiGetRole.from_dict(_roles)

        superset_user_api_get = cls(
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            active=active,
            changed_by=changed_by,
            changed_on=changed_on,
            created_by=created_by,
            created_on=created_on,
            fail_login_count=fail_login_count,
            groups=groups,
            id=id,
            last_login=last_login,
            login_count=login_count,
            roles=roles,
        )

        superset_user_api_get.additional_properties = d
        return superset_user_api_get

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

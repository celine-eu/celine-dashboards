from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.theme_rest_api_get_user import ThemeRestApiGetUser
    from ..models.theme_rest_api_get_user_1 import ThemeRestApiGetUser1


T = TypeVar("T", bound="ThemeRestApiGet")


@_attrs_define
class ThemeRestApiGet:
    """
    Attributes:
        changed_by (ThemeRestApiGetUser | Unset):
        changed_on_delta_humanized (Any | Unset):
        created_by (ThemeRestApiGetUser1 | Unset):
        id (int | Unset):
        is_system (bool | Unset):
        is_system_dark (bool | Unset):
        is_system_default (bool | Unset):
        json_data (None | str | Unset):
        theme_name (None | str | Unset):
        uuid (None | Unset | UUID):
    """

    changed_by: ThemeRestApiGetUser | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    created_by: ThemeRestApiGetUser1 | Unset = UNSET
    id: int | Unset = UNSET
    is_system: bool | Unset = UNSET
    is_system_dark: bool | Unset = UNSET
    is_system_default: bool | Unset = UNSET
    json_data: None | str | Unset = UNSET
    theme_name: None | str | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on_delta_humanized = self.changed_on_delta_humanized

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        id = self.id

        is_system = self.is_system

        is_system_dark = self.is_system_dark

        is_system_default = self.is_system_default

        json_data: None | str | Unset
        if isinstance(self.json_data, Unset):
            json_data = UNSET
        else:
            json_data = self.json_data

        theme_name: None | str | Unset
        if isinstance(self.theme_name, Unset):
            theme_name = UNSET
        else:
            theme_name = self.theme_name

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if id is not UNSET:
            field_dict["id"] = id
        if is_system is not UNSET:
            field_dict["is_system"] = is_system
        if is_system_dark is not UNSET:
            field_dict["is_system_dark"] = is_system_dark
        if is_system_default is not UNSET:
            field_dict["is_system_default"] = is_system_default
        if json_data is not UNSET:
            field_dict["json_data"] = json_data
        if theme_name is not UNSET:
            field_dict["theme_name"] = theme_name
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.theme_rest_api_get_user import ThemeRestApiGetUser
        from ..models.theme_rest_api_get_user_1 import ThemeRestApiGetUser1

        d = dict(src_dict)
        _changed_by = d.pop("changed_by", UNSET)
        changed_by: ThemeRestApiGetUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = ThemeRestApiGetUser.from_dict(_changed_by)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: ThemeRestApiGetUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = ThemeRestApiGetUser1.from_dict(_created_by)

        id = d.pop("id", UNSET)

        is_system = d.pop("is_system", UNSET)

        is_system_dark = d.pop("is_system_dark", UNSET)

        is_system_default = d.pop("is_system_default", UNSET)

        def _parse_json_data(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        json_data = _parse_json_data(d.pop("json_data", UNSET))

        def _parse_theme_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        theme_name = _parse_theme_name(d.pop("theme_name", UNSET))

        def _parse_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                uuid_type_0 = UUID(data)

                return uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        uuid = _parse_uuid(d.pop("uuid", UNSET))

        theme_rest_api_get = cls(
            changed_by=changed_by,
            changed_on_delta_humanized=changed_on_delta_humanized,
            created_by=created_by,
            id=id,
            is_system=is_system,
            is_system_dark=is_system_dark,
            is_system_default=is_system_default,
            json_data=json_data,
            theme_name=theme_name,
            uuid=uuid,
        )

        theme_rest_api_get.additional_properties = d
        return theme_rest_api_get

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

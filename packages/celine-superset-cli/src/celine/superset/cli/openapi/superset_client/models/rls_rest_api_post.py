from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.rls_rest_api_post_filter_type import RLSRestApiPostFilterType, check_rls_rest_api_post_filter_type
from ..types import UNSET, Unset

T = TypeVar("T", bound="RLSRestApiPost")


@_attrs_define
class RLSRestApiPost:
    """
    Attributes:
        clause (str): clause_description
        filter_type (RLSRestApiPostFilterType): filter_type_description
        name (str): name_description
        roles (list[int]): roles_description
        tables (list[int]): tables_description
        description (None | str | Unset): description_description
        group_key (None | str | Unset): group_key_description
    """

    clause: str
    filter_type: RLSRestApiPostFilterType
    name: str
    roles: list[int]
    tables: list[int]
    description: None | str | Unset = UNSET
    group_key: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        clause = self.clause

        filter_type: str = self.filter_type

        name = self.name

        roles = self.roles

        tables = self.tables

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        group_key: None | str | Unset
        if isinstance(self.group_key, Unset):
            group_key = UNSET
        else:
            group_key = self.group_key

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "clause": clause,
                "filter_type": filter_type,
                "name": name,
                "roles": roles,
                "tables": tables,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if group_key is not UNSET:
            field_dict["group_key"] = group_key

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        clause = d.pop("clause")

        filter_type = check_rls_rest_api_post_filter_type(d.pop("filter_type"))

        name = d.pop("name")

        roles = cast(list[int], d.pop("roles"))

        tables = cast(list[int], d.pop("tables"))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_group_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group_key = _parse_group_key(d.pop("group_key", UNSET))

        rls_rest_api_post = cls(
            clause=clause,
            filter_type=filter_type,
            name=name,
            roles=roles,
            tables=tables,
            description=description,
            group_key=group_key,
        )

        rls_rest_api_post.additional_properties = d
        return rls_rest_api_post

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

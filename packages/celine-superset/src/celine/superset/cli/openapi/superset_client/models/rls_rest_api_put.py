from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.rls_rest_api_put_filter_type import RLSRestApiPutFilterType, check_rls_rest_api_put_filter_type
from ..types import UNSET, Unset

T = TypeVar("T", bound="RLSRestApiPut")


@_attrs_define
class RLSRestApiPut:
    """
    Attributes:
        clause (str | Unset): clause_description
        description (None | str | Unset): description_description
        filter_type (RLSRestApiPutFilterType | Unset): filter_type_description
        group_key (None | str | Unset): group_key_description
        name (str | Unset): name_description
        roles (list[int] | Unset): roles_description
        tables (list[int] | Unset): tables_description
    """

    clause: str | Unset = UNSET
    description: None | str | Unset = UNSET
    filter_type: RLSRestApiPutFilterType | Unset = UNSET
    group_key: None | str | Unset = UNSET
    name: str | Unset = UNSET
    roles: list[int] | Unset = UNSET
    tables: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        clause = self.clause

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        filter_type: str | Unset = UNSET
        if not isinstance(self.filter_type, Unset):
            filter_type = self.filter_type

        group_key: None | str | Unset
        if isinstance(self.group_key, Unset):
            group_key = UNSET
        else:
            group_key = self.group_key

        name = self.name

        roles: list[int] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles

        tables: list[int] | Unset = UNSET
        if not isinstance(self.tables, Unset):
            tables = self.tables

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if clause is not UNSET:
            field_dict["clause"] = clause
        if description is not UNSET:
            field_dict["description"] = description
        if filter_type is not UNSET:
            field_dict["filter_type"] = filter_type
        if group_key is not UNSET:
            field_dict["group_key"] = group_key
        if name is not UNSET:
            field_dict["name"] = name
        if roles is not UNSET:
            field_dict["roles"] = roles
        if tables is not UNSET:
            field_dict["tables"] = tables

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        clause = d.pop("clause", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        _filter_type = d.pop("filter_type", UNSET)
        filter_type: RLSRestApiPutFilterType | Unset
        if isinstance(_filter_type, Unset):
            filter_type = UNSET
        else:
            filter_type = check_rls_rest_api_put_filter_type(_filter_type)

        def _parse_group_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group_key = _parse_group_key(d.pop("group_key", UNSET))

        name = d.pop("name", UNSET)

        roles = cast(list[int], d.pop("roles", UNSET))

        tables = cast(list[int], d.pop("tables", UNSET))

        rls_rest_api_put = cls(
            clause=clause,
            description=description,
            filter_type=filter_type,
            group_key=group_key,
            name=name,
            roles=roles,
            tables=tables,
        )

        rls_rest_api_put.additional_properties = d
        return rls_rest_api_put

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

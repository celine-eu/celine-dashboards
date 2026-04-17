from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.rls_rest_api_get_filter_type import RLSRestApiGetFilterType, check_rls_rest_api_get_filter_type
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.roles_1 import Roles1
    from ..models.tables import Tables


T = TypeVar("T", bound="RLSRestApiGet")


@_attrs_define
class RLSRestApiGet:
    """
    Attributes:
        clause (str | Unset): clause_description
        description (str | Unset): description_description
        filter_type (RLSRestApiGetFilterType | Unset): filter_type_description
        group_key (str | Unset): group_key_description
        id (int | Unset): id_description
        name (str | Unset): name_description
        roles (list[Roles1] | Unset):
        tables (list[Tables] | Unset):
    """

    clause: str | Unset = UNSET
    description: str | Unset = UNSET
    filter_type: RLSRestApiGetFilterType | Unset = UNSET
    group_key: str | Unset = UNSET
    id: int | Unset = UNSET
    name: str | Unset = UNSET
    roles: list[Roles1] | Unset = UNSET
    tables: list[Tables] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        clause = self.clause

        description = self.description

        filter_type: str | Unset = UNSET
        if not isinstance(self.filter_type, Unset):
            filter_type = self.filter_type

        group_key = self.group_key

        id = self.id

        name = self.name

        roles: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = []
            for roles_item_data in self.roles:
                roles_item = roles_item_data.to_dict()
                roles.append(roles_item)

        tables: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.tables, Unset):
            tables = []
            for tables_item_data in self.tables:
                tables_item = tables_item_data.to_dict()
                tables.append(tables_item)

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
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if roles is not UNSET:
            field_dict["roles"] = roles
        if tables is not UNSET:
            field_dict["tables"] = tables

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.roles_1 import Roles1
        from ..models.tables import Tables

        d = dict(src_dict)
        clause = d.pop("clause", UNSET)

        description = d.pop("description", UNSET)

        _filter_type = d.pop("filter_type", UNSET)
        filter_type: RLSRestApiGetFilterType | Unset
        if isinstance(_filter_type, Unset):
            filter_type = UNSET
        else:
            filter_type = check_rls_rest_api_get_filter_type(_filter_type)

        group_key = d.pop("group_key", UNSET)

        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        _roles = d.pop("roles", UNSET)
        roles: list[Roles1] | Unset = UNSET
        if _roles is not UNSET:
            roles = []
            for roles_item_data in _roles:
                roles_item = Roles1.from_dict(roles_item_data)

                roles.append(roles_item)

        _tables = d.pop("tables", UNSET)
        tables: list[Tables] | Unset = UNSET
        if _tables is not UNSET:
            tables = []
            for tables_item_data in _tables:
                tables_item = Tables.from_dict(tables_item_data)

                tables.append(tables_item)

        rls_rest_api_get = cls(
            clause=clause,
            description=description,
            filter_type=filter_type,
            group_key=group_key,
            id=id,
            name=name,
            roles=roles,
            tables=tables,
        )

        rls_rest_api_get.additional_properties = d
        return rls_rest_api_get

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

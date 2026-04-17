from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_security_user_registrations_info_response_200_add_columns import (
        GetApiV1SecurityUserRegistrationsInfoResponse200AddColumns,
    )
    from ..models.get_api_v1_security_user_registrations_info_response_200_edit_columns import (
        GetApiV1SecurityUserRegistrationsInfoResponse200EditColumns,
    )
    from ..models.get_api_v1_security_user_registrations_info_response_200_filters import (
        GetApiV1SecurityUserRegistrationsInfoResponse200Filters,
    )


T = TypeVar("T", bound="GetApiV1SecurityUserRegistrationsInfoResponse200")


@_attrs_define
class GetApiV1SecurityUserRegistrationsInfoResponse200:
    """
    Attributes:
        add_columns (GetApiV1SecurityUserRegistrationsInfoResponse200AddColumns | Unset):
        edit_columns (GetApiV1SecurityUserRegistrationsInfoResponse200EditColumns | Unset):
        filters (GetApiV1SecurityUserRegistrationsInfoResponse200Filters | Unset):
        permissions (list[str] | Unset): The user permissions for this API resource
    """

    add_columns: GetApiV1SecurityUserRegistrationsInfoResponse200AddColumns | Unset = UNSET
    edit_columns: GetApiV1SecurityUserRegistrationsInfoResponse200EditColumns | Unset = UNSET
    filters: GetApiV1SecurityUserRegistrationsInfoResponse200Filters | Unset = UNSET
    permissions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        add_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.add_columns, Unset):
            add_columns = self.add_columns.to_dict()

        edit_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.edit_columns, Unset):
            edit_columns = self.edit_columns.to_dict()

        filters: dict[str, Any] | Unset = UNSET
        if not isinstance(self.filters, Unset):
            filters = self.filters.to_dict()

        permissions: list[str] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = self.permissions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if add_columns is not UNSET:
            field_dict["add_columns"] = add_columns
        if edit_columns is not UNSET:
            field_dict["edit_columns"] = edit_columns
        if filters is not UNSET:
            field_dict["filters"] = filters
        if permissions is not UNSET:
            field_dict["permissions"] = permissions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_security_user_registrations_info_response_200_add_columns import (
            GetApiV1SecurityUserRegistrationsInfoResponse200AddColumns,
        )
        from ..models.get_api_v1_security_user_registrations_info_response_200_edit_columns import (
            GetApiV1SecurityUserRegistrationsInfoResponse200EditColumns,
        )
        from ..models.get_api_v1_security_user_registrations_info_response_200_filters import (
            GetApiV1SecurityUserRegistrationsInfoResponse200Filters,
        )

        d = dict(src_dict)
        _add_columns = d.pop("add_columns", UNSET)
        add_columns: GetApiV1SecurityUserRegistrationsInfoResponse200AddColumns | Unset
        if isinstance(_add_columns, Unset):
            add_columns = UNSET
        else:
            add_columns = GetApiV1SecurityUserRegistrationsInfoResponse200AddColumns.from_dict(_add_columns)

        _edit_columns = d.pop("edit_columns", UNSET)
        edit_columns: GetApiV1SecurityUserRegistrationsInfoResponse200EditColumns | Unset
        if isinstance(_edit_columns, Unset):
            edit_columns = UNSET
        else:
            edit_columns = GetApiV1SecurityUserRegistrationsInfoResponse200EditColumns.from_dict(_edit_columns)

        _filters = d.pop("filters", UNSET)
        filters: GetApiV1SecurityUserRegistrationsInfoResponse200Filters | Unset
        if isinstance(_filters, Unset):
            filters = UNSET
        else:
            filters = GetApiV1SecurityUserRegistrationsInfoResponse200Filters.from_dict(_filters)

        permissions = cast(list[str], d.pop("permissions", UNSET))

        get_api_v1_security_user_registrations_info_response_200 = cls(
            add_columns=add_columns,
            edit_columns=edit_columns,
            filters=filters,
            permissions=permissions,
        )

        get_api_v1_security_user_registrations_info_response_200.additional_properties = d
        return get_api_v1_security_user_registrations_info_response_200

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

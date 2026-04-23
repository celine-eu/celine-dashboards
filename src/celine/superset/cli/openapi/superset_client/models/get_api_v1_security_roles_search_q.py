from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.get_api_v1_security_roles_search_q_order_column import (
    GetApiV1SecurityRolesSearchQOrderColumn,
    check_get_api_v1_security_roles_search_q_order_column,
)
from ..models.get_api_v1_security_roles_search_q_order_direction import (
    GetApiV1SecurityRolesSearchQOrderDirection,
    check_get_api_v1_security_roles_search_q_order_direction,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_security_roles_search_q_filters_item import GetApiV1SecurityRolesSearchQFiltersItem


T = TypeVar("T", bound="GetApiV1SecurityRolesSearchQ")


@_attrs_define
class GetApiV1SecurityRolesSearchQ:
    """
    Attributes:
        filters (list[GetApiV1SecurityRolesSearchQFiltersItem] | Unset):
        order_column (GetApiV1SecurityRolesSearchQOrderColumn | Unset):  Default: 'id'.
        order_direction (GetApiV1SecurityRolesSearchQOrderDirection | Unset):  Default: 'asc'.
        page (int | Unset):  Default: 0.
        page_size (int | Unset):  Default: 10.
    """

    filters: list[GetApiV1SecurityRolesSearchQFiltersItem] | Unset = UNSET
    order_column: GetApiV1SecurityRolesSearchQOrderColumn | Unset = "id"
    order_direction: GetApiV1SecurityRolesSearchQOrderDirection | Unset = "asc"
    page: int | Unset = 0
    page_size: int | Unset = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        filters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.filters, Unset):
            filters = []
            for filters_item_data in self.filters:
                filters_item = filters_item_data.to_dict()
                filters.append(filters_item)

        order_column: str | Unset = UNSET
        if not isinstance(self.order_column, Unset):
            order_column = self.order_column

        order_direction: str | Unset = UNSET
        if not isinstance(self.order_direction, Unset):
            order_direction = self.order_direction

        page = self.page

        page_size = self.page_size

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if filters is not UNSET:
            field_dict["filters"] = filters
        if order_column is not UNSET:
            field_dict["order_column"] = order_column
        if order_direction is not UNSET:
            field_dict["order_direction"] = order_direction
        if page is not UNSET:
            field_dict["page"] = page
        if page_size is not UNSET:
            field_dict["page_size"] = page_size

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_security_roles_search_q_filters_item import GetApiV1SecurityRolesSearchQFiltersItem

        d = dict(src_dict)
        _filters = d.pop("filters", UNSET)
        filters: list[GetApiV1SecurityRolesSearchQFiltersItem] | Unset = UNSET
        if _filters is not UNSET:
            filters = []
            for filters_item_data in _filters:
                filters_item = GetApiV1SecurityRolesSearchQFiltersItem.from_dict(filters_item_data)

                filters.append(filters_item)

        _order_column = d.pop("order_column", UNSET)
        order_column: GetApiV1SecurityRolesSearchQOrderColumn | Unset
        if isinstance(_order_column, Unset):
            order_column = UNSET
        else:
            order_column = check_get_api_v1_security_roles_search_q_order_column(_order_column)

        _order_direction = d.pop("order_direction", UNSET)
        order_direction: GetApiV1SecurityRolesSearchQOrderDirection | Unset
        if isinstance(_order_direction, Unset):
            order_direction = UNSET
        else:
            order_direction = check_get_api_v1_security_roles_search_q_order_direction(_order_direction)

        page = d.pop("page", UNSET)

        page_size = d.pop("page_size", UNSET)

        get_api_v1_security_roles_search_q = cls(
            filters=filters,
            order_column=order_column,
            order_direction=order_direction,
            page=page,
            page_size=page_size,
        )

        get_api_v1_security_roles_search_q.additional_properties = d
        return get_api_v1_security_roles_search_q

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

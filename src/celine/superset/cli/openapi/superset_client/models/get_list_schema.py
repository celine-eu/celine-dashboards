from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.get_list_schema_keys_item import GetListSchemaKeysItem, check_get_list_schema_keys_item
from ..models.get_list_schema_order_direction import GetListSchemaOrderDirection, check_get_list_schema_order_direction
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_list_schema_filters_item import GetListSchemaFiltersItem


T = TypeVar("T", bound="GetListSchema")


@_attrs_define
class GetListSchema:
    """
    Attributes:
        columns (list[str] | Unset):
        filters (list[GetListSchemaFiltersItem] | Unset):
        keys (list[GetListSchemaKeysItem] | Unset):
        order_column (str | Unset):
        order_direction (GetListSchemaOrderDirection | Unset):
        page (int | Unset):
        page_size (int | Unset):
        select_columns (list[str] | Unset):
    """

    columns: list[str] | Unset = UNSET
    filters: list[GetListSchemaFiltersItem] | Unset = UNSET
    keys: list[GetListSchemaKeysItem] | Unset = UNSET
    order_column: str | Unset = UNSET
    order_direction: GetListSchemaOrderDirection | Unset = UNSET
    page: int | Unset = UNSET
    page_size: int | Unset = UNSET
    select_columns: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        columns: list[str] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = self.columns

        filters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.filters, Unset):
            filters = []
            for filters_item_data in self.filters:
                filters_item = filters_item_data.to_dict()
                filters.append(filters_item)

        keys: list[str] | Unset = UNSET
        if not isinstance(self.keys, Unset):
            keys = []
            for keys_item_data in self.keys:
                keys_item: str = keys_item_data
                keys.append(keys_item)

        order_column = self.order_column

        order_direction: str | Unset = UNSET
        if not isinstance(self.order_direction, Unset):
            order_direction = self.order_direction

        page = self.page

        page_size = self.page_size

        select_columns: list[str] | Unset = UNSET
        if not isinstance(self.select_columns, Unset):
            select_columns = self.select_columns

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if columns is not UNSET:
            field_dict["columns"] = columns
        if filters is not UNSET:
            field_dict["filters"] = filters
        if keys is not UNSET:
            field_dict["keys"] = keys
        if order_column is not UNSET:
            field_dict["order_column"] = order_column
        if order_direction is not UNSET:
            field_dict["order_direction"] = order_direction
        if page is not UNSET:
            field_dict["page"] = page
        if page_size is not UNSET:
            field_dict["page_size"] = page_size
        if select_columns is not UNSET:
            field_dict["select_columns"] = select_columns

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_list_schema_filters_item import GetListSchemaFiltersItem

        d = dict(src_dict)
        columns = cast(list[str], d.pop("columns", UNSET))

        _filters = d.pop("filters", UNSET)
        filters: list[GetListSchemaFiltersItem] | Unset = UNSET
        if _filters is not UNSET:
            filters = []
            for filters_item_data in _filters:
                filters_item = GetListSchemaFiltersItem.from_dict(filters_item_data)

                filters.append(filters_item)

        _keys = d.pop("keys", UNSET)
        keys: list[GetListSchemaKeysItem] | Unset = UNSET
        if _keys is not UNSET:
            keys = []
            for keys_item_data in _keys:
                keys_item = check_get_list_schema_keys_item(keys_item_data)

                keys.append(keys_item)

        order_column = d.pop("order_column", UNSET)

        _order_direction = d.pop("order_direction", UNSET)
        order_direction: GetListSchemaOrderDirection | Unset
        if isinstance(_order_direction, Unset):
            order_direction = UNSET
        else:
            order_direction = check_get_list_schema_order_direction(_order_direction)

        page = d.pop("page", UNSET)

        page_size = d.pop("page_size", UNSET)

        select_columns = cast(list[str], d.pop("select_columns", UNSET))

        get_list_schema = cls(
            columns=columns,
            filters=filters,
            keys=keys,
            order_column=order_column,
            order_direction=order_direction,
            page=page,
            page_size=page_size,
            select_columns=select_columns,
        )

        get_list_schema.additional_properties = d
        return get_list_schema

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

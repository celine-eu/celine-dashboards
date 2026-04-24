from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.query_execution_response_schema_columns_item import QueryExecutionResponseSchemaColumnsItem
    from ..models.query_execution_response_schema_data_item import QueryExecutionResponseSchemaDataItem
    from ..models.query_execution_response_schema_expanded_columns_item import (
        QueryExecutionResponseSchemaExpandedColumnsItem,
    )
    from ..models.query_execution_response_schema_selected_columns_item import (
        QueryExecutionResponseSchemaSelectedColumnsItem,
    )
    from ..models.query_result import QueryResult


T = TypeVar("T", bound="QueryExecutionResponseSchema")


@_attrs_define
class QueryExecutionResponseSchema:
    """
    Attributes:
        columns (list[QueryExecutionResponseSchemaColumnsItem] | Unset):
        data (list[QueryExecutionResponseSchemaDataItem] | Unset):
        expanded_columns (list[QueryExecutionResponseSchemaExpandedColumnsItem] | Unset):
        query (QueryResult | Unset):
        query_id (int | Unset):
        selected_columns (list[QueryExecutionResponseSchemaSelectedColumnsItem] | Unset):
        status (str | Unset):
    """

    columns: list[QueryExecutionResponseSchemaColumnsItem] | Unset = UNSET
    data: list[QueryExecutionResponseSchemaDataItem] | Unset = UNSET
    expanded_columns: list[QueryExecutionResponseSchemaExpandedColumnsItem] | Unset = UNSET
    query: QueryResult | Unset = UNSET
    query_id: int | Unset = UNSET
    selected_columns: list[QueryExecutionResponseSchemaSelectedColumnsItem] | Unset = UNSET
    status: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        columns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = []
            for columns_item_data in self.columns:
                columns_item = columns_item_data.to_dict()
                columns.append(columns_item)

        data: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.data, Unset):
            data = []
            for data_item_data in self.data:
                data_item = data_item_data.to_dict()
                data.append(data_item)

        expanded_columns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.expanded_columns, Unset):
            expanded_columns = []
            for expanded_columns_item_data in self.expanded_columns:
                expanded_columns_item = expanded_columns_item_data.to_dict()
                expanded_columns.append(expanded_columns_item)

        query: dict[str, Any] | Unset = UNSET
        if not isinstance(self.query, Unset):
            query = self.query.to_dict()

        query_id = self.query_id

        selected_columns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.selected_columns, Unset):
            selected_columns = []
            for selected_columns_item_data in self.selected_columns:
                selected_columns_item = selected_columns_item_data.to_dict()
                selected_columns.append(selected_columns_item)

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if columns is not UNSET:
            field_dict["columns"] = columns
        if data is not UNSET:
            field_dict["data"] = data
        if expanded_columns is not UNSET:
            field_dict["expanded_columns"] = expanded_columns
        if query is not UNSET:
            field_dict["query"] = query
        if query_id is not UNSET:
            field_dict["query_id"] = query_id
        if selected_columns is not UNSET:
            field_dict["selected_columns"] = selected_columns
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.query_execution_response_schema_columns_item import QueryExecutionResponseSchemaColumnsItem
        from ..models.query_execution_response_schema_data_item import QueryExecutionResponseSchemaDataItem
        from ..models.query_execution_response_schema_expanded_columns_item import (
            QueryExecutionResponseSchemaExpandedColumnsItem,
        )
        from ..models.query_execution_response_schema_selected_columns_item import (
            QueryExecutionResponseSchemaSelectedColumnsItem,
        )
        from ..models.query_result import QueryResult

        d = dict(src_dict)
        _columns = d.pop("columns", UNSET)
        columns: list[QueryExecutionResponseSchemaColumnsItem] | Unset = UNSET
        if _columns is not UNSET:
            columns = []
            for columns_item_data in _columns:
                columns_item = QueryExecutionResponseSchemaColumnsItem.from_dict(columns_item_data)

                columns.append(columns_item)

        _data = d.pop("data", UNSET)
        data: list[QueryExecutionResponseSchemaDataItem] | Unset = UNSET
        if _data is not UNSET:
            data = []
            for data_item_data in _data:
                data_item = QueryExecutionResponseSchemaDataItem.from_dict(data_item_data)

                data.append(data_item)

        _expanded_columns = d.pop("expanded_columns", UNSET)
        expanded_columns: list[QueryExecutionResponseSchemaExpandedColumnsItem] | Unset = UNSET
        if _expanded_columns is not UNSET:
            expanded_columns = []
            for expanded_columns_item_data in _expanded_columns:
                expanded_columns_item = QueryExecutionResponseSchemaExpandedColumnsItem.from_dict(
                    expanded_columns_item_data
                )

                expanded_columns.append(expanded_columns_item)

        _query = d.pop("query", UNSET)
        query: QueryResult | Unset
        if isinstance(_query, Unset):
            query = UNSET
        else:
            query = QueryResult.from_dict(_query)

        query_id = d.pop("query_id", UNSET)

        _selected_columns = d.pop("selected_columns", UNSET)
        selected_columns: list[QueryExecutionResponseSchemaSelectedColumnsItem] | Unset = UNSET
        if _selected_columns is not UNSET:
            selected_columns = []
            for selected_columns_item_data in _selected_columns:
                selected_columns_item = QueryExecutionResponseSchemaSelectedColumnsItem.from_dict(
                    selected_columns_item_data
                )

                selected_columns.append(selected_columns_item)

        status = d.pop("status", UNSET)

        query_execution_response_schema = cls(
            columns=columns,
            data=data,
            expanded_columns=expanded_columns,
            query=query,
            query_id=query_id,
            selected_columns=selected_columns,
            status=status,
        )

        query_execution_response_schema.additional_properties = d
        return query_execution_response_schema

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

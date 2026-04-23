from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.query_result import QueryResult
    from ..models.tab_state_extra_json import TabStateExtraJson
    from ..models.tab_state_saved_query_type_0 import TabStateSavedQueryType0
    from ..models.table import Table


T = TypeVar("T", bound="TabState")


@_attrs_define
class TabState:
    """
    Attributes:
        active (bool | Unset):
        autorun (bool | Unset):
        database_id (int | Unset):
        extra_json (TabStateExtraJson | Unset):
        hide_left_bar (bool | Unset):
        id (str | Unset):
        label (str | Unset):
        latest_query (QueryResult | Unset):
        query_limit (int | Unset):
        saved_query (None | TabStateSavedQueryType0 | Unset):
        schema (str | Unset):
        sql (str | Unset):
        table_schemas (list[Table] | Unset):
        user_id (int | Unset):
    """

    active: bool | Unset = UNSET
    autorun: bool | Unset = UNSET
    database_id: int | Unset = UNSET
    extra_json: TabStateExtraJson | Unset = UNSET
    hide_left_bar: bool | Unset = UNSET
    id: str | Unset = UNSET
    label: str | Unset = UNSET
    latest_query: QueryResult | Unset = UNSET
    query_limit: int | Unset = UNSET
    saved_query: None | TabStateSavedQueryType0 | Unset = UNSET
    schema: str | Unset = UNSET
    sql: str | Unset = UNSET
    table_schemas: list[Table] | Unset = UNSET
    user_id: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.tab_state_saved_query_type_0 import TabStateSavedQueryType0

        active = self.active

        autorun = self.autorun

        database_id = self.database_id

        extra_json: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra_json, Unset):
            extra_json = self.extra_json.to_dict()

        hide_left_bar = self.hide_left_bar

        id = self.id

        label = self.label

        latest_query: dict[str, Any] | Unset = UNSET
        if not isinstance(self.latest_query, Unset):
            latest_query = self.latest_query.to_dict()

        query_limit = self.query_limit

        saved_query: dict[str, Any] | None | Unset
        if isinstance(self.saved_query, Unset):
            saved_query = UNSET
        elif isinstance(self.saved_query, TabStateSavedQueryType0):
            saved_query = self.saved_query.to_dict()
        else:
            saved_query = self.saved_query

        schema = self.schema

        sql = self.sql

        table_schemas: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.table_schemas, Unset):
            table_schemas = []
            for table_schemas_item_data in self.table_schemas:
                table_schemas_item = table_schemas_item_data.to_dict()
                table_schemas.append(table_schemas_item)

        user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if active is not UNSET:
            field_dict["active"] = active
        if autorun is not UNSET:
            field_dict["autorun"] = autorun
        if database_id is not UNSET:
            field_dict["database_id"] = database_id
        if extra_json is not UNSET:
            field_dict["extra_json"] = extra_json
        if hide_left_bar is not UNSET:
            field_dict["hide_left_bar"] = hide_left_bar
        if id is not UNSET:
            field_dict["id"] = id
        if label is not UNSET:
            field_dict["label"] = label
        if latest_query is not UNSET:
            field_dict["latest_query"] = latest_query
        if query_limit is not UNSET:
            field_dict["query_limit"] = query_limit
        if saved_query is not UNSET:
            field_dict["saved_query"] = saved_query
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if table_schemas is not UNSET:
            field_dict["table_schemas"] = table_schemas
        if user_id is not UNSET:
            field_dict["user_id"] = user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.query_result import QueryResult
        from ..models.tab_state_extra_json import TabStateExtraJson
        from ..models.tab_state_saved_query_type_0 import TabStateSavedQueryType0
        from ..models.table import Table

        d = dict(src_dict)
        active = d.pop("active", UNSET)

        autorun = d.pop("autorun", UNSET)

        database_id = d.pop("database_id", UNSET)

        _extra_json = d.pop("extra_json", UNSET)
        extra_json: TabStateExtraJson | Unset
        if isinstance(_extra_json, Unset):
            extra_json = UNSET
        else:
            extra_json = TabStateExtraJson.from_dict(_extra_json)

        hide_left_bar = d.pop("hide_left_bar", UNSET)

        id = d.pop("id", UNSET)

        label = d.pop("label", UNSET)

        _latest_query = d.pop("latest_query", UNSET)
        latest_query: QueryResult | Unset
        if isinstance(_latest_query, Unset):
            latest_query = UNSET
        else:
            latest_query = QueryResult.from_dict(_latest_query)

        query_limit = d.pop("query_limit", UNSET)

        def _parse_saved_query(data: object) -> None | TabStateSavedQueryType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                saved_query_type_0 = TabStateSavedQueryType0.from_dict(data)

                return saved_query_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | TabStateSavedQueryType0 | Unset, data)

        saved_query = _parse_saved_query(d.pop("saved_query", UNSET))

        schema = d.pop("schema", UNSET)

        sql = d.pop("sql", UNSET)

        _table_schemas = d.pop("table_schemas", UNSET)
        table_schemas: list[Table] | Unset = UNSET
        if _table_schemas is not UNSET:
            table_schemas = []
            for table_schemas_item_data in _table_schemas:
                table_schemas_item = Table.from_dict(table_schemas_item_data)

                table_schemas.append(table_schemas_item)

        user_id = d.pop("user_id", UNSET)

        tab_state = cls(
            active=active,
            autorun=autorun,
            database_id=database_id,
            extra_json=extra_json,
            hide_left_bar=hide_left_bar,
            id=id,
            label=label,
            latest_query=latest_query,
            query_limit=query_limit,
            saved_query=saved_query,
            schema=schema,
            sql=sql,
            table_schemas=table_schemas,
            user_id=user_id,
        )

        tab_state.additional_properties = d
        return tab_state

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

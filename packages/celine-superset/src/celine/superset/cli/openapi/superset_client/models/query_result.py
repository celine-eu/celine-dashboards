from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.query_result_extra import QueryResultExtra


T = TypeVar("T", bound="QueryResult")


@_attrs_define
class QueryResult:
    """
    Attributes:
        changed_on (datetime.datetime | Unset):
        ctas (bool | Unset):
        db (str | Unset):
        db_id (int | Unset):
        end_dttm (float | Unset):
        error_message (None | str | Unset):
        executed_sql (str | Unset):
        extra (QueryResultExtra | Unset):
        id (str | Unset):
        limit (int | Unset):
        limiting_factor (str | Unset):
        progress (int | Unset):
        query_id (int | Unset):
        results_key (str | Unset):
        rows (int | Unset):
        schema (str | Unset):
        server_id (int | Unset):
        sql (str | Unset):
        sql_editor_id (str | Unset):
        start_dttm (float | Unset):
        state (str | Unset):
        tab (str | Unset):
        temp_schema (None | str | Unset):
        temp_table (None | str | Unset):
        tracking_url (None | str | Unset):
        user (str | Unset):
        user_id (int | Unset):
    """

    changed_on: datetime.datetime | Unset = UNSET
    ctas: bool | Unset = UNSET
    db: str | Unset = UNSET
    db_id: int | Unset = UNSET
    end_dttm: float | Unset = UNSET
    error_message: None | str | Unset = UNSET
    executed_sql: str | Unset = UNSET
    extra: QueryResultExtra | Unset = UNSET
    id: str | Unset = UNSET
    limit: int | Unset = UNSET
    limiting_factor: str | Unset = UNSET
    progress: int | Unset = UNSET
    query_id: int | Unset = UNSET
    results_key: str | Unset = UNSET
    rows: int | Unset = UNSET
    schema: str | Unset = UNSET
    server_id: int | Unset = UNSET
    sql: str | Unset = UNSET
    sql_editor_id: str | Unset = UNSET
    start_dttm: float | Unset = UNSET
    state: str | Unset = UNSET
    tab: str | Unset = UNSET
    temp_schema: None | str | Unset = UNSET
    temp_table: None | str | Unset = UNSET
    tracking_url: None | str | Unset = UNSET
    user: str | Unset = UNSET
    user_id: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        changed_on: str | Unset = UNSET
        if not isinstance(self.changed_on, Unset):
            changed_on = self.changed_on.isoformat()

        ctas = self.ctas

        db = self.db

        db_id = self.db_id

        end_dttm = self.end_dttm

        error_message: None | str | Unset
        if isinstance(self.error_message, Unset):
            error_message = UNSET
        else:
            error_message = self.error_message

        executed_sql = self.executed_sql

        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        id = self.id

        limit = self.limit

        limiting_factor = self.limiting_factor

        progress = self.progress

        query_id = self.query_id

        results_key = self.results_key

        rows = self.rows

        schema = self.schema

        server_id = self.server_id

        sql = self.sql

        sql_editor_id = self.sql_editor_id

        start_dttm = self.start_dttm

        state = self.state

        tab = self.tab

        temp_schema: None | str | Unset
        if isinstance(self.temp_schema, Unset):
            temp_schema = UNSET
        else:
            temp_schema = self.temp_schema

        temp_table: None | str | Unset
        if isinstance(self.temp_table, Unset):
            temp_table = UNSET
        else:
            temp_table = self.temp_table

        tracking_url: None | str | Unset
        if isinstance(self.tracking_url, Unset):
            tracking_url = UNSET
        else:
            tracking_url = self.tracking_url

        user = self.user

        user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if ctas is not UNSET:
            field_dict["ctas"] = ctas
        if db is not UNSET:
            field_dict["db"] = db
        if db_id is not UNSET:
            field_dict["dbId"] = db_id
        if end_dttm is not UNSET:
            field_dict["endDttm"] = end_dttm
        if error_message is not UNSET:
            field_dict["errorMessage"] = error_message
        if executed_sql is not UNSET:
            field_dict["executedSql"] = executed_sql
        if extra is not UNSET:
            field_dict["extra"] = extra
        if id is not UNSET:
            field_dict["id"] = id
        if limit is not UNSET:
            field_dict["limit"] = limit
        if limiting_factor is not UNSET:
            field_dict["limitingFactor"] = limiting_factor
        if progress is not UNSET:
            field_dict["progress"] = progress
        if query_id is not UNSET:
            field_dict["queryId"] = query_id
        if results_key is not UNSET:
            field_dict["resultsKey"] = results_key
        if rows is not UNSET:
            field_dict["rows"] = rows
        if schema is not UNSET:
            field_dict["schema"] = schema
        if server_id is not UNSET:
            field_dict["serverId"] = server_id
        if sql is not UNSET:
            field_dict["sql"] = sql
        if sql_editor_id is not UNSET:
            field_dict["sqlEditorId"] = sql_editor_id
        if start_dttm is not UNSET:
            field_dict["startDttm"] = start_dttm
        if state is not UNSET:
            field_dict["state"] = state
        if tab is not UNSET:
            field_dict["tab"] = tab
        if temp_schema is not UNSET:
            field_dict["tempSchema"] = temp_schema
        if temp_table is not UNSET:
            field_dict["tempTable"] = temp_table
        if tracking_url is not UNSET:
            field_dict["trackingUrl"] = tracking_url
        if user is not UNSET:
            field_dict["user"] = user
        if user_id is not UNSET:
            field_dict["userId"] = user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.query_result_extra import QueryResultExtra

        d = dict(src_dict)
        _changed_on = d.pop("changed_on", UNSET)
        changed_on: datetime.datetime | Unset
        if isinstance(_changed_on, Unset):
            changed_on = UNSET
        else:
            changed_on = isoparse(_changed_on)

        ctas = d.pop("ctas", UNSET)

        db = d.pop("db", UNSET)

        db_id = d.pop("dbId", UNSET)

        end_dttm = d.pop("endDttm", UNSET)

        def _parse_error_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error_message = _parse_error_message(d.pop("errorMessage", UNSET))

        executed_sql = d.pop("executedSql", UNSET)

        _extra = d.pop("extra", UNSET)
        extra: QueryResultExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = QueryResultExtra.from_dict(_extra)

        id = d.pop("id", UNSET)

        limit = d.pop("limit", UNSET)

        limiting_factor = d.pop("limitingFactor", UNSET)

        progress = d.pop("progress", UNSET)

        query_id = d.pop("queryId", UNSET)

        results_key = d.pop("resultsKey", UNSET)

        rows = d.pop("rows", UNSET)

        schema = d.pop("schema", UNSET)

        server_id = d.pop("serverId", UNSET)

        sql = d.pop("sql", UNSET)

        sql_editor_id = d.pop("sqlEditorId", UNSET)

        start_dttm = d.pop("startDttm", UNSET)

        state = d.pop("state", UNSET)

        tab = d.pop("tab", UNSET)

        def _parse_temp_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        temp_schema = _parse_temp_schema(d.pop("tempSchema", UNSET))

        def _parse_temp_table(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        temp_table = _parse_temp_table(d.pop("tempTable", UNSET))

        def _parse_tracking_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tracking_url = _parse_tracking_url(d.pop("trackingUrl", UNSET))

        user = d.pop("user", UNSET)

        user_id = d.pop("userId", UNSET)

        query_result = cls(
            changed_on=changed_on,
            ctas=ctas,
            db=db,
            db_id=db_id,
            end_dttm=end_dttm,
            error_message=error_message,
            executed_sql=executed_sql,
            extra=extra,
            id=id,
            limit=limit,
            limiting_factor=limiting_factor,
            progress=progress,
            query_id=query_id,
            results_key=results_key,
            rows=rows,
            schema=schema,
            server_id=server_id,
            sql=sql,
            sql_editor_id=sql_editor_id,
            start_dttm=start_dttm,
            state=state,
            tab=tab,
            temp_schema=temp_schema,
            temp_table=temp_table,
            tracking_url=tracking_url,
            user=user,
            user_id=user_id,
        )

        query_result.additional_properties = d
        return query_result

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

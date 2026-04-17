from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.query_rest_api_get_database import QueryRestApiGetDatabase


T = TypeVar("T", bound="QueryRestApiGet")


@_attrs_define
class QueryRestApiGet:
    """
    Attributes:
        client_id (str):
        database (QueryRestApiGetDatabase):
        changed_on (datetime.datetime | None | Unset):
        end_result_backend_time (float | None | Unset):
        end_time (float | None | Unset):
        error_message (None | str | Unset):
        executed_sql (None | str | Unset):
        id (int | Unset):
        limit (int | None | Unset):
        progress (int | None | Unset):
        results_key (None | str | Unset):
        rows (int | None | Unset):
        schema (None | str | Unset):
        select_as_cta (bool | None | Unset):
        select_as_cta_used (bool | None | Unset):
        select_sql (None | str | Unset):
        sql (None | str | Unset):
        sql_editor_id (None | str | Unset):
        start_running_time (float | None | Unset):
        start_time (float | None | Unset):
        status (None | str | Unset):
        tab_name (None | str | Unset):
        tmp_schema_name (None | str | Unset):
        tmp_table_name (None | str | Unset):
        tracking_url (Any | Unset):
    """

    client_id: str
    database: QueryRestApiGetDatabase
    changed_on: datetime.datetime | None | Unset = UNSET
    end_result_backend_time: float | None | Unset = UNSET
    end_time: float | None | Unset = UNSET
    error_message: None | str | Unset = UNSET
    executed_sql: None | str | Unset = UNSET
    id: int | Unset = UNSET
    limit: int | None | Unset = UNSET
    progress: int | None | Unset = UNSET
    results_key: None | str | Unset = UNSET
    rows: int | None | Unset = UNSET
    schema: None | str | Unset = UNSET
    select_as_cta: bool | None | Unset = UNSET
    select_as_cta_used: bool | None | Unset = UNSET
    select_sql: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    sql_editor_id: None | str | Unset = UNSET
    start_running_time: float | None | Unset = UNSET
    start_time: float | None | Unset = UNSET
    status: None | str | Unset = UNSET
    tab_name: None | str | Unset = UNSET
    tmp_schema_name: None | str | Unset = UNSET
    tmp_table_name: None | str | Unset = UNSET
    tracking_url: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        client_id = self.client_id

        database = self.database.to_dict()

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        end_result_backend_time: float | None | Unset
        if isinstance(self.end_result_backend_time, Unset):
            end_result_backend_time = UNSET
        else:
            end_result_backend_time = self.end_result_backend_time

        end_time: float | None | Unset
        if isinstance(self.end_time, Unset):
            end_time = UNSET
        else:
            end_time = self.end_time

        error_message: None | str | Unset
        if isinstance(self.error_message, Unset):
            error_message = UNSET
        else:
            error_message = self.error_message

        executed_sql: None | str | Unset
        if isinstance(self.executed_sql, Unset):
            executed_sql = UNSET
        else:
            executed_sql = self.executed_sql

        id = self.id

        limit: int | None | Unset
        if isinstance(self.limit, Unset):
            limit = UNSET
        else:
            limit = self.limit

        progress: int | None | Unset
        if isinstance(self.progress, Unset):
            progress = UNSET
        else:
            progress = self.progress

        results_key: None | str | Unset
        if isinstance(self.results_key, Unset):
            results_key = UNSET
        else:
            results_key = self.results_key

        rows: int | None | Unset
        if isinstance(self.rows, Unset):
            rows = UNSET
        else:
            rows = self.rows

        schema: None | str | Unset
        if isinstance(self.schema, Unset):
            schema = UNSET
        else:
            schema = self.schema

        select_as_cta: bool | None | Unset
        if isinstance(self.select_as_cta, Unset):
            select_as_cta = UNSET
        else:
            select_as_cta = self.select_as_cta

        select_as_cta_used: bool | None | Unset
        if isinstance(self.select_as_cta_used, Unset):
            select_as_cta_used = UNSET
        else:
            select_as_cta_used = self.select_as_cta_used

        select_sql: None | str | Unset
        if isinstance(self.select_sql, Unset):
            select_sql = UNSET
        else:
            select_sql = self.select_sql

        sql: None | str | Unset
        if isinstance(self.sql, Unset):
            sql = UNSET
        else:
            sql = self.sql

        sql_editor_id: None | str | Unset
        if isinstance(self.sql_editor_id, Unset):
            sql_editor_id = UNSET
        else:
            sql_editor_id = self.sql_editor_id

        start_running_time: float | None | Unset
        if isinstance(self.start_running_time, Unset):
            start_running_time = UNSET
        else:
            start_running_time = self.start_running_time

        start_time: float | None | Unset
        if isinstance(self.start_time, Unset):
            start_time = UNSET
        else:
            start_time = self.start_time

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        tab_name: None | str | Unset
        if isinstance(self.tab_name, Unset):
            tab_name = UNSET
        else:
            tab_name = self.tab_name

        tmp_schema_name: None | str | Unset
        if isinstance(self.tmp_schema_name, Unset):
            tmp_schema_name = UNSET
        else:
            tmp_schema_name = self.tmp_schema_name

        tmp_table_name: None | str | Unset
        if isinstance(self.tmp_table_name, Unset):
            tmp_table_name = UNSET
        else:
            tmp_table_name = self.tmp_table_name

        tracking_url = self.tracking_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "client_id": client_id,
                "database": database,
            }
        )
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if end_result_backend_time is not UNSET:
            field_dict["end_result_backend_time"] = end_result_backend_time
        if end_time is not UNSET:
            field_dict["end_time"] = end_time
        if error_message is not UNSET:
            field_dict["error_message"] = error_message
        if executed_sql is not UNSET:
            field_dict["executed_sql"] = executed_sql
        if id is not UNSET:
            field_dict["id"] = id
        if limit is not UNSET:
            field_dict["limit"] = limit
        if progress is not UNSET:
            field_dict["progress"] = progress
        if results_key is not UNSET:
            field_dict["results_key"] = results_key
        if rows is not UNSET:
            field_dict["rows"] = rows
        if schema is not UNSET:
            field_dict["schema"] = schema
        if select_as_cta is not UNSET:
            field_dict["select_as_cta"] = select_as_cta
        if select_as_cta_used is not UNSET:
            field_dict["select_as_cta_used"] = select_as_cta_used
        if select_sql is not UNSET:
            field_dict["select_sql"] = select_sql
        if sql is not UNSET:
            field_dict["sql"] = sql
        if sql_editor_id is not UNSET:
            field_dict["sql_editor_id"] = sql_editor_id
        if start_running_time is not UNSET:
            field_dict["start_running_time"] = start_running_time
        if start_time is not UNSET:
            field_dict["start_time"] = start_time
        if status is not UNSET:
            field_dict["status"] = status
        if tab_name is not UNSET:
            field_dict["tab_name"] = tab_name
        if tmp_schema_name is not UNSET:
            field_dict["tmp_schema_name"] = tmp_schema_name
        if tmp_table_name is not UNSET:
            field_dict["tmp_table_name"] = tmp_table_name
        if tracking_url is not UNSET:
            field_dict["tracking_url"] = tracking_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.query_rest_api_get_database import QueryRestApiGetDatabase

        d = dict(src_dict)
        client_id = d.pop("client_id")

        database = QueryRestApiGetDatabase.from_dict(d.pop("database"))

        def _parse_changed_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                changed_on_type_0 = isoparse(data)

                return changed_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        changed_on = _parse_changed_on(d.pop("changed_on", UNSET))

        def _parse_end_result_backend_time(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        end_result_backend_time = _parse_end_result_backend_time(d.pop("end_result_backend_time", UNSET))

        def _parse_end_time(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        end_time = _parse_end_time(d.pop("end_time", UNSET))

        def _parse_error_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error_message = _parse_error_message(d.pop("error_message", UNSET))

        def _parse_executed_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        executed_sql = _parse_executed_sql(d.pop("executed_sql", UNSET))

        id = d.pop("id", UNSET)

        def _parse_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        limit = _parse_limit(d.pop("limit", UNSET))

        def _parse_progress(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        progress = _parse_progress(d.pop("progress", UNSET))

        def _parse_results_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        results_key = _parse_results_key(d.pop("results_key", UNSET))

        def _parse_rows(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rows = _parse_rows(d.pop("rows", UNSET))

        def _parse_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schema = _parse_schema(d.pop("schema", UNSET))

        def _parse_select_as_cta(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        select_as_cta = _parse_select_as_cta(d.pop("select_as_cta", UNSET))

        def _parse_select_as_cta_used(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        select_as_cta_used = _parse_select_as_cta_used(d.pop("select_as_cta_used", UNSET))

        def _parse_select_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        select_sql = _parse_select_sql(d.pop("select_sql", UNSET))

        def _parse_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql = _parse_sql(d.pop("sql", UNSET))

        def _parse_sql_editor_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql_editor_id = _parse_sql_editor_id(d.pop("sql_editor_id", UNSET))

        def _parse_start_running_time(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        start_running_time = _parse_start_running_time(d.pop("start_running_time", UNSET))

        def _parse_start_time(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        start_time = _parse_start_time(d.pop("start_time", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_tab_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tab_name = _parse_tab_name(d.pop("tab_name", UNSET))

        def _parse_tmp_schema_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tmp_schema_name = _parse_tmp_schema_name(d.pop("tmp_schema_name", UNSET))

        def _parse_tmp_table_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tmp_table_name = _parse_tmp_table_name(d.pop("tmp_table_name", UNSET))

        tracking_url = d.pop("tracking_url", UNSET)

        query_rest_api_get = cls(
            client_id=client_id,
            database=database,
            changed_on=changed_on,
            end_result_backend_time=end_result_backend_time,
            end_time=end_time,
            error_message=error_message,
            executed_sql=executed_sql,
            id=id,
            limit=limit,
            progress=progress,
            results_key=results_key,
            rows=rows,
            schema=schema,
            select_as_cta=select_as_cta,
            select_as_cta_used=select_as_cta_used,
            select_sql=select_sql,
            sql=sql,
            sql_editor_id=sql_editor_id,
            start_running_time=start_running_time,
            start_time=start_time,
            status=status,
            tab_name=tab_name,
            tmp_schema_name=tmp_schema_name,
            tmp_table_name=tmp_table_name,
            tracking_url=tracking_url,
        )

        query_rest_api_get.additional_properties = d
        return query_rest_api_get

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

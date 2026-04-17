from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.database_1 import Database1
    from ..models.user_1 import User1


T = TypeVar("T", bound="QueryRestApiGetList")


@_attrs_define
class QueryRestApiGetList:
    """
    Attributes:
        changed_on (datetime.datetime | Unset):
        database (Database1 | Unset):
        end_time (float | Unset):
        executed_sql (str | Unset):
        id (int | Unset):
        rows (int | Unset):
        schema (str | Unset):
        sql (str | Unset):
        sql_tables (Any | Unset):
        start_time (float | Unset):
        status (str | Unset):
        tab_name (str | Unset):
        tmp_table_name (str | Unset):
        tracking_url (str | Unset):
        user (User1 | Unset):
    """

    changed_on: datetime.datetime | Unset = UNSET
    database: Database1 | Unset = UNSET
    end_time: float | Unset = UNSET
    executed_sql: str | Unset = UNSET
    id: int | Unset = UNSET
    rows: int | Unset = UNSET
    schema: str | Unset = UNSET
    sql: str | Unset = UNSET
    sql_tables: Any | Unset = UNSET
    start_time: float | Unset = UNSET
    status: str | Unset = UNSET
    tab_name: str | Unset = UNSET
    tmp_table_name: str | Unset = UNSET
    tracking_url: str | Unset = UNSET
    user: User1 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        changed_on: str | Unset = UNSET
        if not isinstance(self.changed_on, Unset):
            changed_on = self.changed_on.isoformat()

        database: dict[str, Any] | Unset = UNSET
        if not isinstance(self.database, Unset):
            database = self.database.to_dict()

        end_time = self.end_time

        executed_sql = self.executed_sql

        id = self.id

        rows = self.rows

        schema = self.schema

        sql = self.sql

        sql_tables = self.sql_tables

        start_time = self.start_time

        status = self.status

        tab_name = self.tab_name

        tmp_table_name = self.tmp_table_name

        tracking_url = self.tracking_url

        user: dict[str, Any] | Unset = UNSET
        if not isinstance(self.user, Unset):
            user = self.user.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if database is not UNSET:
            field_dict["database"] = database
        if end_time is not UNSET:
            field_dict["end_time"] = end_time
        if executed_sql is not UNSET:
            field_dict["executed_sql"] = executed_sql
        if id is not UNSET:
            field_dict["id"] = id
        if rows is not UNSET:
            field_dict["rows"] = rows
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if sql_tables is not UNSET:
            field_dict["sql_tables"] = sql_tables
        if start_time is not UNSET:
            field_dict["start_time"] = start_time
        if status is not UNSET:
            field_dict["status"] = status
        if tab_name is not UNSET:
            field_dict["tab_name"] = tab_name
        if tmp_table_name is not UNSET:
            field_dict["tmp_table_name"] = tmp_table_name
        if tracking_url is not UNSET:
            field_dict["tracking_url"] = tracking_url
        if user is not UNSET:
            field_dict["user"] = user

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.database_1 import Database1
        from ..models.user_1 import User1

        d = dict(src_dict)
        _changed_on = d.pop("changed_on", UNSET)
        changed_on: datetime.datetime | Unset
        if isinstance(_changed_on, Unset):
            changed_on = UNSET
        else:
            changed_on = isoparse(_changed_on)

        _database = d.pop("database", UNSET)
        database: Database1 | Unset
        if isinstance(_database, Unset):
            database = UNSET
        else:
            database = Database1.from_dict(_database)

        end_time = d.pop("end_time", UNSET)

        executed_sql = d.pop("executed_sql", UNSET)

        id = d.pop("id", UNSET)

        rows = d.pop("rows", UNSET)

        schema = d.pop("schema", UNSET)

        sql = d.pop("sql", UNSET)

        sql_tables = d.pop("sql_tables", UNSET)

        start_time = d.pop("start_time", UNSET)

        status = d.pop("status", UNSET)

        tab_name = d.pop("tab_name", UNSET)

        tmp_table_name = d.pop("tmp_table_name", UNSET)

        tracking_url = d.pop("tracking_url", UNSET)

        _user = d.pop("user", UNSET)
        user: User1 | Unset
        if isinstance(_user, Unset):
            user = UNSET
        else:
            user = User1.from_dict(_user)

        query_rest_api_get_list = cls(
            changed_on=changed_on,
            database=database,
            end_time=end_time,
            executed_sql=executed_sql,
            id=id,
            rows=rows,
            schema=schema,
            sql=sql,
            sql_tables=sql_tables,
            start_time=start_time,
            status=status,
            tab_name=tab_name,
            tmp_table_name=tmp_table_name,
            tracking_url=tracking_url,
            user=user,
        )

        query_rest_api_get_list.additional_properties = d
        return query_rest_api_get_list

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

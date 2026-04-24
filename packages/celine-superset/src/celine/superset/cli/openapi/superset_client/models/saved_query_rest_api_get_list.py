from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.saved_query_rest_api_get_list_database import SavedQueryRestApiGetListDatabase
    from ..models.saved_query_rest_api_get_list_tag import SavedQueryRestApiGetListTag
    from ..models.saved_query_rest_api_get_list_user import SavedQueryRestApiGetListUser
    from ..models.saved_query_rest_api_get_list_user_1 import SavedQueryRestApiGetListUser1


T = TypeVar("T", bound="SavedQueryRestApiGetList")


@_attrs_define
class SavedQueryRestApiGetList:
    """
    Attributes:
        catalog (None | str | Unset):
        changed_by (SavedQueryRestApiGetListUser | Unset):
        changed_on (datetime.datetime | None | Unset):
        changed_on_delta_humanized (Any | Unset):
        created_by (SavedQueryRestApiGetListUser1 | Unset):
        created_on (datetime.datetime | None | Unset):
        database (SavedQueryRestApiGetListDatabase | Unset):
        db_id (Any | Unset):
        description (None | str | Unset):
        extra (Any | Unset):
        id (int | Unset):
        label (None | str | Unset):
        last_run_delta_humanized (Any | Unset):
        rows (int | None | Unset):
        schema (None | str | Unset):
        sql (None | str | Unset):
        sql_tables (Any | Unset):
        tags (SavedQueryRestApiGetListTag | Unset):
    """

    catalog: None | str | Unset = UNSET
    changed_by: SavedQueryRestApiGetListUser | Unset = UNSET
    changed_on: datetime.datetime | None | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    created_by: SavedQueryRestApiGetListUser1 | Unset = UNSET
    created_on: datetime.datetime | None | Unset = UNSET
    database: SavedQueryRestApiGetListDatabase | Unset = UNSET
    db_id: Any | Unset = UNSET
    description: None | str | Unset = UNSET
    extra: Any | Unset = UNSET
    id: int | Unset = UNSET
    label: None | str | Unset = UNSET
    last_run_delta_humanized: Any | Unset = UNSET
    rows: int | None | Unset = UNSET
    schema: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    sql_tables: Any | Unset = UNSET
    tags: SavedQueryRestApiGetListTag | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        changed_on_delta_humanized = self.changed_on_delta_humanized

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on: None | str | Unset
        if isinstance(self.created_on, Unset):
            created_on = UNSET
        elif isinstance(self.created_on, datetime.datetime):
            created_on = self.created_on.isoformat()
        else:
            created_on = self.created_on

        database: dict[str, Any] | Unset = UNSET
        if not isinstance(self.database, Unset):
            database = self.database.to_dict()

        db_id = self.db_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        extra = self.extra

        id = self.id

        label: None | str | Unset
        if isinstance(self.label, Unset):
            label = UNSET
        else:
            label = self.label

        last_run_delta_humanized = self.last_run_delta_humanized

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

        sql: None | str | Unset
        if isinstance(self.sql, Unset):
            sql = UNSET
        else:
            sql = self.sql

        sql_tables = self.sql_tables

        tags: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on is not UNSET:
            field_dict["created_on"] = created_on
        if database is not UNSET:
            field_dict["database"] = database
        if db_id is not UNSET:
            field_dict["db_id"] = db_id
        if description is not UNSET:
            field_dict["description"] = description
        if extra is not UNSET:
            field_dict["extra"] = extra
        if id is not UNSET:
            field_dict["id"] = id
        if label is not UNSET:
            field_dict["label"] = label
        if last_run_delta_humanized is not UNSET:
            field_dict["last_run_delta_humanized"] = last_run_delta_humanized
        if rows is not UNSET:
            field_dict["rows"] = rows
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if sql_tables is not UNSET:
            field_dict["sql_tables"] = sql_tables
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.saved_query_rest_api_get_list_database import SavedQueryRestApiGetListDatabase
        from ..models.saved_query_rest_api_get_list_tag import SavedQueryRestApiGetListTag
        from ..models.saved_query_rest_api_get_list_user import SavedQueryRestApiGetListUser
        from ..models.saved_query_rest_api_get_list_user_1 import SavedQueryRestApiGetListUser1

        d = dict(src_dict)

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: SavedQueryRestApiGetListUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = SavedQueryRestApiGetListUser.from_dict(_changed_by)

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

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: SavedQueryRestApiGetListUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = SavedQueryRestApiGetListUser1.from_dict(_created_by)

        def _parse_created_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                created_on_type_0 = isoparse(data)

                return created_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        created_on = _parse_created_on(d.pop("created_on", UNSET))

        _database = d.pop("database", UNSET)
        database: SavedQueryRestApiGetListDatabase | Unset
        if isinstance(_database, Unset):
            database = UNSET
        else:
            database = SavedQueryRestApiGetListDatabase.from_dict(_database)

        db_id = d.pop("db_id", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        extra = d.pop("extra", UNSET)

        id = d.pop("id", UNSET)

        def _parse_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        label = _parse_label(d.pop("label", UNSET))

        last_run_delta_humanized = d.pop("last_run_delta_humanized", UNSET)

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

        def _parse_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql = _parse_sql(d.pop("sql", UNSET))

        sql_tables = d.pop("sql_tables", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: SavedQueryRestApiGetListTag | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = SavedQueryRestApiGetListTag.from_dict(_tags)

        saved_query_rest_api_get_list = cls(
            catalog=catalog,
            changed_by=changed_by,
            changed_on=changed_on,
            changed_on_delta_humanized=changed_on_delta_humanized,
            created_by=created_by,
            created_on=created_on,
            database=database,
            db_id=db_id,
            description=description,
            extra=extra,
            id=id,
            label=label,
            last_run_delta_humanized=last_run_delta_humanized,
            rows=rows,
            schema=schema,
            sql=sql,
            sql_tables=sql_tables,
            tags=tags,
        )

        saved_query_rest_api_get_list.additional_properties = d
        return saved_query_rest_api_get_list

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

from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.saved_query_rest_api_get_database import SavedQueryRestApiGetDatabase
    from ..models.saved_query_rest_api_get_user import SavedQueryRestApiGetUser
    from ..models.saved_query_rest_api_get_user_1 import SavedQueryRestApiGetUser1


T = TypeVar("T", bound="SavedQueryRestApiGet")


@_attrs_define
class SavedQueryRestApiGet:
    """
    Attributes:
        catalog (None | str | Unset):
        changed_by (SavedQueryRestApiGetUser | Unset):
        changed_on (datetime.datetime | None | Unset):
        changed_on_delta_humanized (Any | Unset):
        created_by (SavedQueryRestApiGetUser1 | Unset):
        database (SavedQueryRestApiGetDatabase | Unset):
        description (None | str | Unset):
        id (int | Unset):
        label (None | str | Unset):
        schema (None | str | Unset):
        sql (None | str | Unset):
        sql_tables (Any | Unset):
        template_parameters (None | str | Unset):
    """

    catalog: None | str | Unset = UNSET
    changed_by: SavedQueryRestApiGetUser | Unset = UNSET
    changed_on: datetime.datetime | None | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    created_by: SavedQueryRestApiGetUser1 | Unset = UNSET
    database: SavedQueryRestApiGetDatabase | Unset = UNSET
    description: None | str | Unset = UNSET
    id: int | Unset = UNSET
    label: None | str | Unset = UNSET
    schema: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    sql_tables: Any | Unset = UNSET
    template_parameters: None | str | Unset = UNSET
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

        database: dict[str, Any] | Unset = UNSET
        if not isinstance(self.database, Unset):
            database = self.database.to_dict()

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        id = self.id

        label: None | str | Unset
        if isinstance(self.label, Unset):
            label = UNSET
        else:
            label = self.label

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

        template_parameters: None | str | Unset
        if isinstance(self.template_parameters, Unset):
            template_parameters = UNSET
        else:
            template_parameters = self.template_parameters

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
        if database is not UNSET:
            field_dict["database"] = database
        if description is not UNSET:
            field_dict["description"] = description
        if id is not UNSET:
            field_dict["id"] = id
        if label is not UNSET:
            field_dict["label"] = label
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if sql_tables is not UNSET:
            field_dict["sql_tables"] = sql_tables
        if template_parameters is not UNSET:
            field_dict["template_parameters"] = template_parameters

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.saved_query_rest_api_get_database import SavedQueryRestApiGetDatabase
        from ..models.saved_query_rest_api_get_user import SavedQueryRestApiGetUser
        from ..models.saved_query_rest_api_get_user_1 import SavedQueryRestApiGetUser1

        d = dict(src_dict)

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: SavedQueryRestApiGetUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = SavedQueryRestApiGetUser.from_dict(_changed_by)

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
        created_by: SavedQueryRestApiGetUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = SavedQueryRestApiGetUser1.from_dict(_created_by)

        _database = d.pop("database", UNSET)
        database: SavedQueryRestApiGetDatabase | Unset
        if isinstance(_database, Unset):
            database = UNSET
        else:
            database = SavedQueryRestApiGetDatabase.from_dict(_database)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        id = d.pop("id", UNSET)

        def _parse_label(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        label = _parse_label(d.pop("label", UNSET))

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

        def _parse_template_parameters(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_parameters = _parse_template_parameters(d.pop("template_parameters", UNSET))

        saved_query_rest_api_get = cls(
            catalog=catalog,
            changed_by=changed_by,
            changed_on=changed_on,
            changed_on_delta_humanized=changed_on_delta_humanized,
            created_by=created_by,
            database=database,
            description=description,
            id=id,
            label=label,
            schema=schema,
            sql=sql,
            sql_tables=sql_tables,
            template_parameters=template_parameters,
        )

        saved_query_rest_api_get.additional_properties = d
        return saved_query_rest_api_get

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SqlLabPermalinkSchema")


@_attrs_define
class SqlLabPermalinkSchema:
    """
    Attributes:
        db_id (int): The id of the database
        name (str): The label of the editor tab
        sql (str): SQL query text
        autorun (bool | Unset):
        catalog (None | str | Unset): The catalog name of the query
        schema (None | str | Unset): The schema name of the query
        template_params (None | str | Unset): stringfied JSON string for template parameters
    """

    db_id: int
    name: str
    sql: str
    autorun: bool | Unset = UNSET
    catalog: None | str | Unset = UNSET
    schema: None | str | Unset = UNSET
    template_params: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        db_id = self.db_id

        name = self.name

        sql = self.sql

        autorun = self.autorun

        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        schema: None | str | Unset
        if isinstance(self.schema, Unset):
            schema = UNSET
        else:
            schema = self.schema

        template_params: None | str | Unset
        if isinstance(self.template_params, Unset):
            template_params = UNSET
        else:
            template_params = self.template_params

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dbId": db_id,
                "name": name,
                "sql": sql,
            }
        )
        if autorun is not UNSET:
            field_dict["autorun"] = autorun
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if schema is not UNSET:
            field_dict["schema"] = schema
        if template_params is not UNSET:
            field_dict["templateParams"] = template_params

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        db_id = d.pop("dbId")

        name = d.pop("name")

        sql = d.pop("sql")

        autorun = d.pop("autorun", UNSET)

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        def _parse_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schema = _parse_schema(d.pop("schema", UNSET))

        def _parse_template_params(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_params = _parse_template_params(d.pop("templateParams", UNSET))

        sql_lab_permalink_schema = cls(
            db_id=db_id,
            name=name,
            sql=sql,
            autorun=autorun,
            catalog=catalog,
            schema=schema,
            template_params=template_params,
        )

        sql_lab_permalink_schema.additional_properties = d
        return sql_lab_permalink_schema

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

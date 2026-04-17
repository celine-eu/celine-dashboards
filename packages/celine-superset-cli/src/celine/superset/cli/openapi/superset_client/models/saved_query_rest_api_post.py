from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SavedQueryRestApiPost")


@_attrs_define
class SavedQueryRestApiPost:
    """
    Attributes:
        catalog (None | str | Unset):
        db_id (Any | Unset):
        description (None | str | Unset):
        extra_json (None | str | Unset):
        label (None | str | Unset):
        schema (None | str | Unset):
        sql (None | str | Unset):
        template_parameters (None | str | Unset):
    """

    catalog: None | str | Unset = UNSET
    db_id: Any | Unset = UNSET
    description: None | str | Unset = UNSET
    extra_json: None | str | Unset = UNSET
    label: None | str | Unset = UNSET
    schema: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    template_parameters: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        db_id = self.db_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        extra_json: None | str | Unset
        if isinstance(self.extra_json, Unset):
            extra_json = UNSET
        else:
            extra_json = self.extra_json

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
        if db_id is not UNSET:
            field_dict["db_id"] = db_id
        if description is not UNSET:
            field_dict["description"] = description
        if extra_json is not UNSET:
            field_dict["extra_json"] = extra_json
        if label is not UNSET:
            field_dict["label"] = label
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if template_parameters is not UNSET:
            field_dict["template_parameters"] = template_parameters

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        db_id = d.pop("db_id", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_extra_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extra_json = _parse_extra_json(d.pop("extra_json", UNSET))

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

        def _parse_template_parameters(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_parameters = _parse_template_parameters(d.pop("template_parameters", UNSET))

        saved_query_rest_api_post = cls(
            catalog=catalog,
            db_id=db_id,
            description=description,
            extra_json=extra_json,
            label=label,
            schema=schema,
            sql=sql,
            template_parameters=template_parameters,
        )

        saved_query_rest_api_post.additional_properties = d
        return saved_query_rest_api_post

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatasetRestApiPost")


@_attrs_define
class DatasetRestApiPost:
    """
    Attributes:
        database (int):
        table_name (str):
        always_filter_main_dttm (bool | Unset):  Default: False.
        catalog (None | str | Unset):
        external_url (None | str | Unset):
        is_managed_externally (bool | None | Unset):
        normalize_columns (bool | Unset):  Default: False.
        owners (list[int] | Unset):
        schema (None | str | Unset):
        sql (None | str | Unset):
        template_params (None | str | Unset):
        uuid (None | Unset | UUID):
    """

    database: int
    table_name: str
    always_filter_main_dttm: bool | Unset = False
    catalog: None | str | Unset = UNSET
    external_url: None | str | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    normalize_columns: bool | Unset = False
    owners: list[int] | Unset = UNSET
    schema: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    template_params: None | str | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database = self.database

        table_name = self.table_name

        always_filter_main_dttm = self.always_filter_main_dttm

        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        external_url: None | str | Unset
        if isinstance(self.external_url, Unset):
            external_url = UNSET
        else:
            external_url = self.external_url

        is_managed_externally: bool | None | Unset
        if isinstance(self.is_managed_externally, Unset):
            is_managed_externally = UNSET
        else:
            is_managed_externally = self.is_managed_externally

        normalize_columns = self.normalize_columns

        owners: list[int] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners

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

        template_params: None | str | Unset
        if isinstance(self.template_params, Unset):
            template_params = UNSET
        else:
            template_params = self.template_params

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "database": database,
                "table_name": table_name,
            }
        )
        if always_filter_main_dttm is not UNSET:
            field_dict["always_filter_main_dttm"] = always_filter_main_dttm
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if external_url is not UNSET:
            field_dict["external_url"] = external_url
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if normalize_columns is not UNSET:
            field_dict["normalize_columns"] = normalize_columns
        if owners is not UNSET:
            field_dict["owners"] = owners
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if template_params is not UNSET:
            field_dict["template_params"] = template_params
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        database = d.pop("database")

        table_name = d.pop("table_name")

        always_filter_main_dttm = d.pop("always_filter_main_dttm", UNSET)

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        def _parse_external_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        external_url = _parse_external_url(d.pop("external_url", UNSET))

        def _parse_is_managed_externally(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_managed_externally = _parse_is_managed_externally(d.pop("is_managed_externally", UNSET))

        normalize_columns = d.pop("normalize_columns", UNSET)

        owners = cast(list[int], d.pop("owners", UNSET))

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

        def _parse_template_params(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_params = _parse_template_params(d.pop("template_params", UNSET))

        def _parse_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                uuid_type_0 = UUID(data)

                return uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        uuid = _parse_uuid(d.pop("uuid", UNSET))

        dataset_rest_api_post = cls(
            database=database,
            table_name=table_name,
            always_filter_main_dttm=always_filter_main_dttm,
            catalog=catalog,
            external_url=external_url,
            is_managed_externally=is_managed_externally,
            normalize_columns=normalize_columns,
            owners=owners,
            schema=schema,
            sql=sql,
            template_params=template_params,
            uuid=uuid,
        )

        dataset_rest_api_post.additional_properties = d
        return dataset_rest_api_post

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

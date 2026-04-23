from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExecutePayloadSchema")


@_attrs_define
class ExecutePayloadSchema:
    """
    Attributes:
        database_id (int):
        sql (str):
        catalog (None | str | Unset):
        client_id (None | str | Unset):
        ctas_method (None | str | Unset):
        expand_data (bool | None | Unset):
        json (bool | None | Unset):
        query_limit (int | None | Unset):
        run_async (bool | None | Unset):
        schema (None | str | Unset):
        select_as_cta (bool | None | Unset):
        sql_editor_id (None | str | Unset):
        tab (None | str | Unset):
        template_params (None | str | Unset):
        tmp_table_name (None | str | Unset):
    """

    database_id: int
    sql: str
    catalog: None | str | Unset = UNSET
    client_id: None | str | Unset = UNSET
    ctas_method: None | str | Unset = UNSET
    expand_data: bool | None | Unset = UNSET
    json: bool | None | Unset = UNSET
    query_limit: int | None | Unset = UNSET
    run_async: bool | None | Unset = UNSET
    schema: None | str | Unset = UNSET
    select_as_cta: bool | None | Unset = UNSET
    sql_editor_id: None | str | Unset = UNSET
    tab: None | str | Unset = UNSET
    template_params: None | str | Unset = UNSET
    tmp_table_name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database_id = self.database_id

        sql = self.sql

        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        client_id: None | str | Unset
        if isinstance(self.client_id, Unset):
            client_id = UNSET
        else:
            client_id = self.client_id

        ctas_method: None | str | Unset
        if isinstance(self.ctas_method, Unset):
            ctas_method = UNSET
        else:
            ctas_method = self.ctas_method

        expand_data: bool | None | Unset
        if isinstance(self.expand_data, Unset):
            expand_data = UNSET
        else:
            expand_data = self.expand_data

        json: bool | None | Unset
        if isinstance(self.json, Unset):
            json = UNSET
        else:
            json = self.json

        query_limit: int | None | Unset
        if isinstance(self.query_limit, Unset):
            query_limit = UNSET
        else:
            query_limit = self.query_limit

        run_async: bool | None | Unset
        if isinstance(self.run_async, Unset):
            run_async = UNSET
        else:
            run_async = self.run_async

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

        sql_editor_id: None | str | Unset
        if isinstance(self.sql_editor_id, Unset):
            sql_editor_id = UNSET
        else:
            sql_editor_id = self.sql_editor_id

        tab: None | str | Unset
        if isinstance(self.tab, Unset):
            tab = UNSET
        else:
            tab = self.tab

        template_params: None | str | Unset
        if isinstance(self.template_params, Unset):
            template_params = UNSET
        else:
            template_params = self.template_params

        tmp_table_name: None | str | Unset
        if isinstance(self.tmp_table_name, Unset):
            tmp_table_name = UNSET
        else:
            tmp_table_name = self.tmp_table_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "database_id": database_id,
                "sql": sql,
            }
        )
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if client_id is not UNSET:
            field_dict["client_id"] = client_id
        if ctas_method is not UNSET:
            field_dict["ctas_method"] = ctas_method
        if expand_data is not UNSET:
            field_dict["expand_data"] = expand_data
        if json is not UNSET:
            field_dict["json"] = json
        if query_limit is not UNSET:
            field_dict["queryLimit"] = query_limit
        if run_async is not UNSET:
            field_dict["runAsync"] = run_async
        if schema is not UNSET:
            field_dict["schema"] = schema
        if select_as_cta is not UNSET:
            field_dict["select_as_cta"] = select_as_cta
        if sql_editor_id is not UNSET:
            field_dict["sql_editor_id"] = sql_editor_id
        if tab is not UNSET:
            field_dict["tab"] = tab
        if template_params is not UNSET:
            field_dict["templateParams"] = template_params
        if tmp_table_name is not UNSET:
            field_dict["tmp_table_name"] = tmp_table_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        database_id = d.pop("database_id")

        sql = d.pop("sql")

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        def _parse_client_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        client_id = _parse_client_id(d.pop("client_id", UNSET))

        def _parse_ctas_method(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ctas_method = _parse_ctas_method(d.pop("ctas_method", UNSET))

        def _parse_expand_data(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        expand_data = _parse_expand_data(d.pop("expand_data", UNSET))

        def _parse_json(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        json = _parse_json(d.pop("json", UNSET))

        def _parse_query_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        query_limit = _parse_query_limit(d.pop("queryLimit", UNSET))

        def _parse_run_async(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        run_async = _parse_run_async(d.pop("runAsync", UNSET))

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

        def _parse_sql_editor_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql_editor_id = _parse_sql_editor_id(d.pop("sql_editor_id", UNSET))

        def _parse_tab(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tab = _parse_tab(d.pop("tab", UNSET))

        def _parse_template_params(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_params = _parse_template_params(d.pop("templateParams", UNSET))

        def _parse_tmp_table_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tmp_table_name = _parse_tmp_table_name(d.pop("tmp_table_name", UNSET))

        execute_payload_schema = cls(
            database_id=database_id,
            sql=sql,
            catalog=catalog,
            client_id=client_id,
            ctas_method=ctas_method,
            expand_data=expand_data,
            json=json,
            query_limit=query_limit,
            run_async=run_async,
            schema=schema,
            select_as_cta=select_as_cta,
            sql_editor_id=sql_editor_id,
            tab=tab,
            template_params=template_params,
            tmp_table_name=tmp_table_name,
        )

        execute_payload_schema.additional_properties = d
        return execute_payload_schema

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

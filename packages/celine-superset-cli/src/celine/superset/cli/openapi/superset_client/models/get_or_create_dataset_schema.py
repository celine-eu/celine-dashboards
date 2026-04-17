from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GetOrCreateDatasetSchema")


@_attrs_define
class GetOrCreateDatasetSchema:
    """
    Attributes:
        database_id (int): ID of database table belongs to
        table_name (str): Name of table
        always_filter_main_dttm (bool | Unset):  Default: False.
        catalog (None | str | Unset): The catalog the table belongs to
        normalize_columns (bool | Unset):  Default: False.
        schema (None | str | Unset): The schema the table belongs to
        template_params (str | Unset): Template params for the table
    """

    database_id: int
    table_name: str
    always_filter_main_dttm: bool | Unset = False
    catalog: None | str | Unset = UNSET
    normalize_columns: bool | Unset = False
    schema: None | str | Unset = UNSET
    template_params: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database_id = self.database_id

        table_name = self.table_name

        always_filter_main_dttm = self.always_filter_main_dttm

        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        normalize_columns = self.normalize_columns

        schema: None | str | Unset
        if isinstance(self.schema, Unset):
            schema = UNSET
        else:
            schema = self.schema

        template_params = self.template_params

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "database_id": database_id,
                "table_name": table_name,
            }
        )
        if always_filter_main_dttm is not UNSET:
            field_dict["always_filter_main_dttm"] = always_filter_main_dttm
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if normalize_columns is not UNSET:
            field_dict["normalize_columns"] = normalize_columns
        if schema is not UNSET:
            field_dict["schema"] = schema
        if template_params is not UNSET:
            field_dict["template_params"] = template_params

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        database_id = d.pop("database_id")

        table_name = d.pop("table_name")

        always_filter_main_dttm = d.pop("always_filter_main_dttm", UNSET)

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        normalize_columns = d.pop("normalize_columns", UNSET)

        def _parse_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schema = _parse_schema(d.pop("schema", UNSET))

        template_params = d.pop("template_params", UNSET)

        get_or_create_dataset_schema = cls(
            database_id=database_id,
            table_name=table_name,
            always_filter_main_dttm=always_filter_main_dttm,
            catalog=catalog,
            normalize_columns=normalize_columns,
            schema=schema,
            template_params=template_params,
        )

        get_or_create_dataset_schema.additional_properties = d
        return get_or_create_dataset_schema

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

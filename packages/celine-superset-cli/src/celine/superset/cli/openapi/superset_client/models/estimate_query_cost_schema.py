from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.estimate_query_cost_schema_template_params import EstimateQueryCostSchemaTemplateParams


T = TypeVar("T", bound="EstimateQueryCostSchema")


@_attrs_define
class EstimateQueryCostSchema:
    """
    Attributes:
        database_id (int): The database id
        sql (str): The SQL query to estimate
        catalog (None | str | Unset): The database catalog
        schema (None | str | Unset): The database schema
        template_params (EstimateQueryCostSchemaTemplateParams | Unset): The SQL query template params
    """

    database_id: int
    sql: str
    catalog: None | str | Unset = UNSET
    schema: None | str | Unset = UNSET
    template_params: EstimateQueryCostSchemaTemplateParams | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database_id = self.database_id

        sql = self.sql

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

        template_params: dict[str, Any] | Unset = UNSET
        if not isinstance(self.template_params, Unset):
            template_params = self.template_params.to_dict()

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
        if schema is not UNSET:
            field_dict["schema"] = schema
        if template_params is not UNSET:
            field_dict["template_params"] = template_params

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.estimate_query_cost_schema_template_params import EstimateQueryCostSchemaTemplateParams

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

        def _parse_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schema = _parse_schema(d.pop("schema", UNSET))

        _template_params = d.pop("template_params", UNSET)
        template_params: EstimateQueryCostSchemaTemplateParams | Unset
        if isinstance(_template_params, Unset):
            template_params = UNSET
        else:
            template_params = EstimateQueryCostSchemaTemplateParams.from_dict(_template_params)

        estimate_query_cost_schema = cls(
            database_id=database_id,
            sql=sql,
            catalog=catalog,
            schema=schema,
            template_params=template_params,
        )

        estimate_query_cost_schema.additional_properties = d
        return estimate_query_cost_schema

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

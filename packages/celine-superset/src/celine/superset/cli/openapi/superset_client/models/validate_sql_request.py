from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.validate_sql_request_template_params_type_0 import ValidateSQLRequestTemplateParamsType0


T = TypeVar("T", bound="ValidateSQLRequest")


@_attrs_define
class ValidateSQLRequest:
    """
    Attributes:
        sql (str): SQL statement to validate
        catalog (None | str | Unset):
        schema (None | str | Unset):
        template_params (None | Unset | ValidateSQLRequestTemplateParamsType0):
    """

    sql: str
    catalog: None | str | Unset = UNSET
    schema: None | str | Unset = UNSET
    template_params: None | Unset | ValidateSQLRequestTemplateParamsType0 = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.validate_sql_request_template_params_type_0 import ValidateSQLRequestTemplateParamsType0

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

        template_params: dict[str, Any] | None | Unset
        if isinstance(self.template_params, Unset):
            template_params = UNSET
        elif isinstance(self.template_params, ValidateSQLRequestTemplateParamsType0):
            template_params = self.template_params.to_dict()
        else:
            template_params = self.template_params

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
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
        from ..models.validate_sql_request_template_params_type_0 import ValidateSQLRequestTemplateParamsType0

        d = dict(src_dict)
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

        def _parse_template_params(data: object) -> None | Unset | ValidateSQLRequestTemplateParamsType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                template_params_type_0 = ValidateSQLRequestTemplateParamsType0.from_dict(data)

                return template_params_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | ValidateSQLRequestTemplateParamsType0, data)

        template_params = _parse_template_params(d.pop("template_params", UNSET))

        validate_sql_request = cls(
            sql=sql,
            catalog=catalog,
            schema=schema,
            template_params=template_params,
        )

        validate_sql_request.additional_properties = d
        return validate_sql_request

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

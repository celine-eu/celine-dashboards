from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.datasource_datasource_type import DatasourceDatasourceType, check_datasource_datasource_type
from ..types import UNSET, Unset

T = TypeVar("T", bound="Datasource")


@_attrs_define
class Datasource:
    """
    Attributes:
        datasource_type (DatasourceDatasourceType): The type of dataset/datasource identified on `datasource_id`.
        catalog (None | str | Unset): Datasource catalog
        database_name (str | Unset): Datasource name
        datasource_name (str | Unset): The datasource name.
        schema (str | Unset): Datasource schema
    """

    datasource_type: DatasourceDatasourceType
    catalog: None | str | Unset = UNSET
    database_name: str | Unset = UNSET
    datasource_name: str | Unset = UNSET
    schema: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        datasource_type: str = self.datasource_type

        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        database_name = self.database_name

        datasource_name = self.datasource_name

        schema = self.schema

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "datasource_type": datasource_type,
            }
        )
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if database_name is not UNSET:
            field_dict["database_name"] = database_name
        if datasource_name is not UNSET:
            field_dict["datasource_name"] = datasource_name
        if schema is not UNSET:
            field_dict["schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        datasource_type = check_datasource_datasource_type(d.pop("datasource_type"))

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        database_name = d.pop("database_name", UNSET)

        datasource_name = d.pop("datasource_name", UNSET)

        schema = d.pop("schema", UNSET)

        datasource = cls(
            datasource_type=datasource_type,
            catalog=catalog,
            database_name=database_name,
            datasource_name=datasource_name,
            schema=schema,
        )

        datasource.additional_properties = d
        return datasource

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

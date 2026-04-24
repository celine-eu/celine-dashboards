from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.table_metadata_options_response import TableMetadataOptionsResponse


T = TypeVar("T", bound="TableMetadataForeignKeysIndexesResponse")


@_attrs_define
class TableMetadataForeignKeysIndexesResponse:
    """
    Attributes:
        column_names (list[str] | Unset):
        name (str | Unset): The name of the foreign key or index
        options (TableMetadataOptionsResponse | Unset):
        referred_columns (list[str] | Unset):
        referred_schema (str | Unset):
        referred_table (str | Unset):
        type_ (str | Unset):
    """

    column_names: list[str] | Unset = UNSET
    name: str | Unset = UNSET
    options: TableMetadataOptionsResponse | Unset = UNSET
    referred_columns: list[str] | Unset = UNSET
    referred_schema: str | Unset = UNSET
    referred_table: str | Unset = UNSET
    type_: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        column_names: list[str] | Unset = UNSET
        if not isinstance(self.column_names, Unset):
            column_names = self.column_names

        name = self.name

        options: dict[str, Any] | Unset = UNSET
        if not isinstance(self.options, Unset):
            options = self.options.to_dict()

        referred_columns: list[str] | Unset = UNSET
        if not isinstance(self.referred_columns, Unset):
            referred_columns = self.referred_columns

        referred_schema = self.referred_schema

        referred_table = self.referred_table

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if column_names is not UNSET:
            field_dict["column_names"] = column_names
        if name is not UNSET:
            field_dict["name"] = name
        if options is not UNSET:
            field_dict["options"] = options
        if referred_columns is not UNSET:
            field_dict["referred_columns"] = referred_columns
        if referred_schema is not UNSET:
            field_dict["referred_schema"] = referred_schema
        if referred_table is not UNSET:
            field_dict["referred_table"] = referred_table
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.table_metadata_options_response import TableMetadataOptionsResponse

        d = dict(src_dict)
        column_names = cast(list[str], d.pop("column_names", UNSET))

        name = d.pop("name", UNSET)

        _options = d.pop("options", UNSET)
        options: TableMetadataOptionsResponse | Unset
        if isinstance(_options, Unset):
            options = UNSET
        else:
            options = TableMetadataOptionsResponse.from_dict(_options)

        referred_columns = cast(list[str], d.pop("referred_columns", UNSET))

        referred_schema = d.pop("referred_schema", UNSET)

        referred_table = d.pop("referred_table", UNSET)

        type_ = d.pop("type", UNSET)

        table_metadata_foreign_keys_indexes_response = cls(
            column_names=column_names,
            name=name,
            options=options,
            referred_columns=referred_columns,
            referred_schema=referred_schema,
            referred_table=referred_table,
            type_=type_,
        )

        table_metadata_foreign_keys_indexes_response.additional_properties = d
        return table_metadata_foreign_keys_indexes_response

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

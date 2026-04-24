from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.table_metadata_columns_response import TableMetadataColumnsResponse
    from ..models.table_metadata_foreign_keys_indexes_response import TableMetadataForeignKeysIndexesResponse
    from ..models.table_metadata_primary_key_response import TableMetadataPrimaryKeyResponse


T = TypeVar("T", bound="TableMetadataResponseSchema")


@_attrs_define
class TableMetadataResponseSchema:
    """
    Attributes:
        columns (list[TableMetadataColumnsResponse] | Unset): A list of columns and their metadata
        foreign_keys (list[TableMetadataForeignKeysIndexesResponse] | Unset): A list of foreign keys and their metadata
        indexes (list[TableMetadataForeignKeysIndexesResponse] | Unset): A list of indexes and their metadata
        name (str | Unset): The name of the table
        primary_key (TableMetadataPrimaryKeyResponse | Unset):
        select_star (str | Unset): SQL select star
    """

    columns: list[TableMetadataColumnsResponse] | Unset = UNSET
    foreign_keys: list[TableMetadataForeignKeysIndexesResponse] | Unset = UNSET
    indexes: list[TableMetadataForeignKeysIndexesResponse] | Unset = UNSET
    name: str | Unset = UNSET
    primary_key: TableMetadataPrimaryKeyResponse | Unset = UNSET
    select_star: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        columns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = []
            for columns_item_data in self.columns:
                columns_item = columns_item_data.to_dict()
                columns.append(columns_item)

        foreign_keys: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.foreign_keys, Unset):
            foreign_keys = []
            for foreign_keys_item_data in self.foreign_keys:
                foreign_keys_item = foreign_keys_item_data.to_dict()
                foreign_keys.append(foreign_keys_item)

        indexes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.indexes, Unset):
            indexes = []
            for indexes_item_data in self.indexes:
                indexes_item = indexes_item_data.to_dict()
                indexes.append(indexes_item)

        name = self.name

        primary_key: dict[str, Any] | Unset = UNSET
        if not isinstance(self.primary_key, Unset):
            primary_key = self.primary_key.to_dict()

        select_star = self.select_star

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if columns is not UNSET:
            field_dict["columns"] = columns
        if foreign_keys is not UNSET:
            field_dict["foreignKeys"] = foreign_keys
        if indexes is not UNSET:
            field_dict["indexes"] = indexes
        if name is not UNSET:
            field_dict["name"] = name
        if primary_key is not UNSET:
            field_dict["primaryKey"] = primary_key
        if select_star is not UNSET:
            field_dict["selectStar"] = select_star

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.table_metadata_columns_response import TableMetadataColumnsResponse
        from ..models.table_metadata_foreign_keys_indexes_response import TableMetadataForeignKeysIndexesResponse
        from ..models.table_metadata_primary_key_response import TableMetadataPrimaryKeyResponse

        d = dict(src_dict)
        _columns = d.pop("columns", UNSET)
        columns: list[TableMetadataColumnsResponse] | Unset = UNSET
        if _columns is not UNSET:
            columns = []
            for columns_item_data in _columns:
                columns_item = TableMetadataColumnsResponse.from_dict(columns_item_data)

                columns.append(columns_item)

        _foreign_keys = d.pop("foreignKeys", UNSET)
        foreign_keys: list[TableMetadataForeignKeysIndexesResponse] | Unset = UNSET
        if _foreign_keys is not UNSET:
            foreign_keys = []
            for foreign_keys_item_data in _foreign_keys:
                foreign_keys_item = TableMetadataForeignKeysIndexesResponse.from_dict(foreign_keys_item_data)

                foreign_keys.append(foreign_keys_item)

        _indexes = d.pop("indexes", UNSET)
        indexes: list[TableMetadataForeignKeysIndexesResponse] | Unset = UNSET
        if _indexes is not UNSET:
            indexes = []
            for indexes_item_data in _indexes:
                indexes_item = TableMetadataForeignKeysIndexesResponse.from_dict(indexes_item_data)

                indexes.append(indexes_item)

        name = d.pop("name", UNSET)

        _primary_key = d.pop("primaryKey", UNSET)
        primary_key: TableMetadataPrimaryKeyResponse | Unset
        if isinstance(_primary_key, Unset):
            primary_key = UNSET
        else:
            primary_key = TableMetadataPrimaryKeyResponse.from_dict(_primary_key)

        select_star = d.pop("selectStar", UNSET)

        table_metadata_response_schema = cls(
            columns=columns,
            foreign_keys=foreign_keys,
            indexes=indexes,
            name=name,
            primary_key=primary_key,
            select_star=select_star,
        )

        table_metadata_response_schema.additional_properties = d
        return table_metadata_response_schema

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

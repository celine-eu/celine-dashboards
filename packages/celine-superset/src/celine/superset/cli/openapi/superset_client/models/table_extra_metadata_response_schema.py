from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.table_extra_metadata_response_schema_clustering import TableExtraMetadataResponseSchemaClustering
    from ..models.table_extra_metadata_response_schema_metadata import TableExtraMetadataResponseSchemaMetadata
    from ..models.table_extra_metadata_response_schema_partitions import TableExtraMetadataResponseSchemaPartitions


T = TypeVar("T", bound="TableExtraMetadataResponseSchema")


@_attrs_define
class TableExtraMetadataResponseSchema:
    """
    Attributes:
        clustering (TableExtraMetadataResponseSchemaClustering | Unset):
        metadata (TableExtraMetadataResponseSchemaMetadata | Unset):
        partitions (TableExtraMetadataResponseSchemaPartitions | Unset):
    """

    clustering: TableExtraMetadataResponseSchemaClustering | Unset = UNSET
    metadata: TableExtraMetadataResponseSchemaMetadata | Unset = UNSET
    partitions: TableExtraMetadataResponseSchemaPartitions | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        clustering: dict[str, Any] | Unset = UNSET
        if not isinstance(self.clustering, Unset):
            clustering = self.clustering.to_dict()

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        partitions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.partitions, Unset):
            partitions = self.partitions.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if clustering is not UNSET:
            field_dict["clustering"] = clustering
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if partitions is not UNSET:
            field_dict["partitions"] = partitions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.table_extra_metadata_response_schema_clustering import TableExtraMetadataResponseSchemaClustering
        from ..models.table_extra_metadata_response_schema_metadata import TableExtraMetadataResponseSchemaMetadata
        from ..models.table_extra_metadata_response_schema_partitions import TableExtraMetadataResponseSchemaPartitions

        d = dict(src_dict)
        _clustering = d.pop("clustering", UNSET)
        clustering: TableExtraMetadataResponseSchemaClustering | Unset
        if isinstance(_clustering, Unset):
            clustering = UNSET
        else:
            clustering = TableExtraMetadataResponseSchemaClustering.from_dict(_clustering)

        _metadata = d.pop("metadata", UNSET)
        metadata: TableExtraMetadataResponseSchemaMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = TableExtraMetadataResponseSchemaMetadata.from_dict(_metadata)

        _partitions = d.pop("partitions", UNSET)
        partitions: TableExtraMetadataResponseSchemaPartitions | Unset
        if isinstance(_partitions, Unset):
            partitions = UNSET
        else:
            partitions = TableExtraMetadataResponseSchemaPartitions.from_dict(_partitions)

        table_extra_metadata_response_schema = cls(
            clustering=clustering,
            metadata=metadata,
            partitions=partitions,
        )

        table_extra_metadata_response_schema.additional_properties = d
        return table_extra_metadata_response_schema

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

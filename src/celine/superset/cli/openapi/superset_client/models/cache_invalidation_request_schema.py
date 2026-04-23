from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.datasource import Datasource


T = TypeVar("T", bound="CacheInvalidationRequestSchema")


@_attrs_define
class CacheInvalidationRequestSchema:
    """
    Attributes:
        datasource_uids (list[str] | Unset): The uid of the dataset/datasource this new chart will use. A complete
            datasource identification needs `datasource_uid`
        datasources (list[Datasource] | Unset): A list of the data source and database names
    """

    datasource_uids: list[str] | Unset = UNSET
    datasources: list[Datasource] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        datasource_uids: list[str] | Unset = UNSET
        if not isinstance(self.datasource_uids, Unset):
            datasource_uids = self.datasource_uids

        datasources: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.datasources, Unset):
            datasources = []
            for datasources_item_data in self.datasources:
                datasources_item = datasources_item_data.to_dict()
                datasources.append(datasources_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if datasource_uids is not UNSET:
            field_dict["datasource_uids"] = datasource_uids
        if datasources is not UNSET:
            field_dict["datasources"] = datasources

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.datasource import Datasource

        d = dict(src_dict)
        datasource_uids = cast(list[str], d.pop("datasource_uids", UNSET))

        _datasources = d.pop("datasources", UNSET)
        datasources: list[Datasource] | Unset = UNSET
        if _datasources is not UNSET:
            datasources = []
            for datasources_item_data in _datasources:
                datasources_item = Datasource.from_dict(datasources_item_data)

                datasources.append(datasources_item)

        cache_invalidation_request_schema = cls(
            datasource_uids=datasource_uids,
            datasources=datasources,
        )

        cache_invalidation_request_schema.additional_properties = d
        return cache_invalidation_request_schema

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_related_dashboard_json_metadata import DatasetRelatedDashboardJsonMetadata


T = TypeVar("T", bound="DatasetRelatedDashboard")


@_attrs_define
class DatasetRelatedDashboard:
    """
    Attributes:
        id (int | Unset):
        json_metadata (DatasetRelatedDashboardJsonMetadata | Unset):
        slug (str | Unset):
        title (str | Unset):
    """

    id: int | Unset = UNSET
    json_metadata: DatasetRelatedDashboardJsonMetadata | Unset = UNSET
    slug: str | Unset = UNSET
    title: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        json_metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.json_metadata, Unset):
            json_metadata = self.json_metadata.to_dict()

        slug = self.slug

        title = self.title

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if json_metadata is not UNSET:
            field_dict["json_metadata"] = json_metadata
        if slug is not UNSET:
            field_dict["slug"] = slug
        if title is not UNSET:
            field_dict["title"] = title

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset_related_dashboard_json_metadata import DatasetRelatedDashboardJsonMetadata

        d = dict(src_dict)
        id = d.pop("id", UNSET)

        _json_metadata = d.pop("json_metadata", UNSET)
        json_metadata: DatasetRelatedDashboardJsonMetadata | Unset
        if isinstance(_json_metadata, Unset):
            json_metadata = UNSET
        else:
            json_metadata = DatasetRelatedDashboardJsonMetadata.from_dict(_json_metadata)

        slug = d.pop("slug", UNSET)

        title = d.pop("title", UNSET)

        dataset_related_dashboard = cls(
            id=id,
            json_metadata=json_metadata,
            slug=slug,
            title=title,
        )

        dataset_related_dashboard.additional_properties = d
        return dataset_related_dashboard

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatabaseSchemasQuerySchema")


@_attrs_define
class DatabaseSchemasQuerySchema:
    """
    Attributes:
        catalog (str | Unset):
        force (bool | Unset):
        upload_allowed (bool | Unset):
    """

    catalog: str | Unset = UNSET
    force: bool | Unset = UNSET
    upload_allowed: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        catalog = self.catalog

        force = self.force

        upload_allowed = self.upload_allowed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if force is not UNSET:
            field_dict["force"] = force
        if upload_allowed is not UNSET:
            field_dict["upload_allowed"] = upload_allowed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        catalog = d.pop("catalog", UNSET)

        force = d.pop("force", UNSET)

        upload_allowed = d.pop("upload_allowed", UNSET)

        database_schemas_query_schema = cls(
            catalog=catalog,
            force=force,
            upload_allowed=upload_allowed,
        )

        database_schemas_query_schema.additional_properties = d
        return database_schemas_query_schema

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatasetRestApiGetDatabase")


@_attrs_define
class DatasetRestApiGetDatabase:
    """
    Attributes:
        database_name (str):
        allow_multi_catalog (Any | Unset):
        backend (Any | Unset):
        id (int | Unset):
        uuid (None | Unset | UUID):
    """

    database_name: str
    allow_multi_catalog: Any | Unset = UNSET
    backend: Any | Unset = UNSET
    id: int | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database_name = self.database_name

        allow_multi_catalog = self.allow_multi_catalog

        backend = self.backend

        id = self.id

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "database_name": database_name,
            }
        )
        if allow_multi_catalog is not UNSET:
            field_dict["allow_multi_catalog"] = allow_multi_catalog
        if backend is not UNSET:
            field_dict["backend"] = backend
        if id is not UNSET:
            field_dict["id"] = id
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        database_name = d.pop("database_name")

        allow_multi_catalog = d.pop("allow_multi_catalog", UNSET)

        backend = d.pop("backend", UNSET)

        id = d.pop("id", UNSET)

        def _parse_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                uuid_type_0 = UUID(data)

                return uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        uuid = _parse_uuid(d.pop("uuid", UNSET))

        dataset_rest_api_get_database = cls(
            database_name=database_name,
            allow_multi_catalog=allow_multi_catalog,
            backend=backend,
            id=id,
            uuid=uuid,
        )

        dataset_rest_api_get_database.additional_properties = d
        return dataset_rest_api_get_database

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

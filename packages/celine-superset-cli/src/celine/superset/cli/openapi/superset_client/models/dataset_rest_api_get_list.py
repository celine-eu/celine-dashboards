from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_rest_api_get_list_database import DatasetRestApiGetListDatabase
    from ..models.dataset_rest_api_get_list_user import DatasetRestApiGetListUser
    from ..models.dataset_rest_api_get_list_user_1 import DatasetRestApiGetListUser1


T = TypeVar("T", bound="DatasetRestApiGetList")


@_attrs_define
class DatasetRestApiGetList:
    """
    Attributes:
        database (DatasetRestApiGetListDatabase):
        table_name (str):
        catalog (None | str | Unset):
        changed_by (DatasetRestApiGetListUser | Unset):
        changed_by_name (Any | Unset):
        changed_on_delta_humanized (Any | Unset):
        changed_on_utc (Any | Unset):
        datasource_type (Any | Unset):
        default_endpoint (None | str | Unset):
        description (None | str | Unset):
        explore_url (Any | Unset):
        extra (None | str | Unset):
        id (int | Unset):
        kind (Any | Unset):
        owners (DatasetRestApiGetListUser1 | Unset):
        schema (None | str | Unset):
        sql (None | str | Unset):
        uuid (None | Unset | UUID):
    """

    database: DatasetRestApiGetListDatabase
    table_name: str
    catalog: None | str | Unset = UNSET
    changed_by: DatasetRestApiGetListUser | Unset = UNSET
    changed_by_name: Any | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    changed_on_utc: Any | Unset = UNSET
    datasource_type: Any | Unset = UNSET
    default_endpoint: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    explore_url: Any | Unset = UNSET
    extra: None | str | Unset = UNSET
    id: int | Unset = UNSET
    kind: Any | Unset = UNSET
    owners: DatasetRestApiGetListUser1 | Unset = UNSET
    schema: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database = self.database.to_dict()

        table_name = self.table_name

        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_by_name = self.changed_by_name

        changed_on_delta_humanized = self.changed_on_delta_humanized

        changed_on_utc = self.changed_on_utc

        datasource_type = self.datasource_type

        default_endpoint: None | str | Unset
        if isinstance(self.default_endpoint, Unset):
            default_endpoint = UNSET
        else:
            default_endpoint = self.default_endpoint

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        explore_url = self.explore_url

        extra: None | str | Unset
        if isinstance(self.extra, Unset):
            extra = UNSET
        else:
            extra = self.extra

        id = self.id

        kind = self.kind

        owners: dict[str, Any] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners.to_dict()

        schema: None | str | Unset
        if isinstance(self.schema, Unset):
            schema = UNSET
        else:
            schema = self.schema

        sql: None | str | Unset
        if isinstance(self.sql, Unset):
            sql = UNSET
        else:
            sql = self.sql

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
                "database": database,
                "table_name": table_name,
            }
        )
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_by_name is not UNSET:
            field_dict["changed_by_name"] = changed_by_name
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if changed_on_utc is not UNSET:
            field_dict["changed_on_utc"] = changed_on_utc
        if datasource_type is not UNSET:
            field_dict["datasource_type"] = datasource_type
        if default_endpoint is not UNSET:
            field_dict["default_endpoint"] = default_endpoint
        if description is not UNSET:
            field_dict["description"] = description
        if explore_url is not UNSET:
            field_dict["explore_url"] = explore_url
        if extra is not UNSET:
            field_dict["extra"] = extra
        if id is not UNSET:
            field_dict["id"] = id
        if kind is not UNSET:
            field_dict["kind"] = kind
        if owners is not UNSET:
            field_dict["owners"] = owners
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset_rest_api_get_list_database import DatasetRestApiGetListDatabase
        from ..models.dataset_rest_api_get_list_user import DatasetRestApiGetListUser
        from ..models.dataset_rest_api_get_list_user_1 import DatasetRestApiGetListUser1

        d = dict(src_dict)
        database = DatasetRestApiGetListDatabase.from_dict(d.pop("database"))

        table_name = d.pop("table_name")

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: DatasetRestApiGetListUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = DatasetRestApiGetListUser.from_dict(_changed_by)

        changed_by_name = d.pop("changed_by_name", UNSET)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        changed_on_utc = d.pop("changed_on_utc", UNSET)

        datasource_type = d.pop("datasource_type", UNSET)

        def _parse_default_endpoint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        default_endpoint = _parse_default_endpoint(d.pop("default_endpoint", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        explore_url = d.pop("explore_url", UNSET)

        def _parse_extra(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extra = _parse_extra(d.pop("extra", UNSET))

        id = d.pop("id", UNSET)

        kind = d.pop("kind", UNSET)

        _owners = d.pop("owners", UNSET)
        owners: DatasetRestApiGetListUser1 | Unset
        if isinstance(_owners, Unset):
            owners = UNSET
        else:
            owners = DatasetRestApiGetListUser1.from_dict(_owners)

        def _parse_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schema = _parse_schema(d.pop("schema", UNSET))

        def _parse_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql = _parse_sql(d.pop("sql", UNSET))

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

        dataset_rest_api_get_list = cls(
            database=database,
            table_name=table_name,
            catalog=catalog,
            changed_by=changed_by,
            changed_by_name=changed_by_name,
            changed_on_delta_humanized=changed_on_delta_humanized,
            changed_on_utc=changed_on_utc,
            datasource_type=datasource_type,
            default_endpoint=default_endpoint,
            description=description,
            explore_url=explore_url,
            extra=extra,
            id=id,
            kind=kind,
            owners=owners,
            schema=schema,
            sql=sql,
            uuid=uuid,
        )

        dataset_rest_api_get_list.additional_properties = d
        return dataset_rest_api_get_list

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

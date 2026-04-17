from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatabaseRestApiGet")


@_attrs_define
class DatabaseRestApiGet:
    """
    Attributes:
        database_name (str):
        allow_ctas (bool | None | Unset):
        allow_cvas (bool | None | Unset):
        allow_dml (bool | None | Unset):
        allow_file_upload (bool | None | Unset):
        allow_run_async (bool | None | Unset):
        backend (Any | Unset):
        cache_timeout (int | None | Unset):
        configuration_method (None | str | Unset):
        driver (Any | Unset):
        engine_information (Any | Unset):
        expose_in_sqllab (bool | None | Unset):
        force_ctas_schema (None | str | Unset):
        id (int | Unset):
        impersonate_user (bool | None | Unset):
        is_managed_externally (bool | Unset):
        uuid (None | Unset | UUID):
    """

    database_name: str
    allow_ctas: bool | None | Unset = UNSET
    allow_cvas: bool | None | Unset = UNSET
    allow_dml: bool | None | Unset = UNSET
    allow_file_upload: bool | None | Unset = UNSET
    allow_run_async: bool | None | Unset = UNSET
    backend: Any | Unset = UNSET
    cache_timeout: int | None | Unset = UNSET
    configuration_method: None | str | Unset = UNSET
    driver: Any | Unset = UNSET
    engine_information: Any | Unset = UNSET
    expose_in_sqllab: bool | None | Unset = UNSET
    force_ctas_schema: None | str | Unset = UNSET
    id: int | Unset = UNSET
    impersonate_user: bool | None | Unset = UNSET
    is_managed_externally: bool | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database_name = self.database_name

        allow_ctas: bool | None | Unset
        if isinstance(self.allow_ctas, Unset):
            allow_ctas = UNSET
        else:
            allow_ctas = self.allow_ctas

        allow_cvas: bool | None | Unset
        if isinstance(self.allow_cvas, Unset):
            allow_cvas = UNSET
        else:
            allow_cvas = self.allow_cvas

        allow_dml: bool | None | Unset
        if isinstance(self.allow_dml, Unset):
            allow_dml = UNSET
        else:
            allow_dml = self.allow_dml

        allow_file_upload: bool | None | Unset
        if isinstance(self.allow_file_upload, Unset):
            allow_file_upload = UNSET
        else:
            allow_file_upload = self.allow_file_upload

        allow_run_async: bool | None | Unset
        if isinstance(self.allow_run_async, Unset):
            allow_run_async = UNSET
        else:
            allow_run_async = self.allow_run_async

        backend = self.backend

        cache_timeout: int | None | Unset
        if isinstance(self.cache_timeout, Unset):
            cache_timeout = UNSET
        else:
            cache_timeout = self.cache_timeout

        configuration_method: None | str | Unset
        if isinstance(self.configuration_method, Unset):
            configuration_method = UNSET
        else:
            configuration_method = self.configuration_method

        driver = self.driver

        engine_information = self.engine_information

        expose_in_sqllab: bool | None | Unset
        if isinstance(self.expose_in_sqllab, Unset):
            expose_in_sqllab = UNSET
        else:
            expose_in_sqllab = self.expose_in_sqllab

        force_ctas_schema: None | str | Unset
        if isinstance(self.force_ctas_schema, Unset):
            force_ctas_schema = UNSET
        else:
            force_ctas_schema = self.force_ctas_schema

        id = self.id

        impersonate_user: bool | None | Unset
        if isinstance(self.impersonate_user, Unset):
            impersonate_user = UNSET
        else:
            impersonate_user = self.impersonate_user

        is_managed_externally = self.is_managed_externally

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
        if allow_ctas is not UNSET:
            field_dict["allow_ctas"] = allow_ctas
        if allow_cvas is not UNSET:
            field_dict["allow_cvas"] = allow_cvas
        if allow_dml is not UNSET:
            field_dict["allow_dml"] = allow_dml
        if allow_file_upload is not UNSET:
            field_dict["allow_file_upload"] = allow_file_upload
        if allow_run_async is not UNSET:
            field_dict["allow_run_async"] = allow_run_async
        if backend is not UNSET:
            field_dict["backend"] = backend
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if configuration_method is not UNSET:
            field_dict["configuration_method"] = configuration_method
        if driver is not UNSET:
            field_dict["driver"] = driver
        if engine_information is not UNSET:
            field_dict["engine_information"] = engine_information
        if expose_in_sqllab is not UNSET:
            field_dict["expose_in_sqllab"] = expose_in_sqllab
        if force_ctas_schema is not UNSET:
            field_dict["force_ctas_schema"] = force_ctas_schema
        if id is not UNSET:
            field_dict["id"] = id
        if impersonate_user is not UNSET:
            field_dict["impersonate_user"] = impersonate_user
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        database_name = d.pop("database_name")

        def _parse_allow_ctas(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_ctas = _parse_allow_ctas(d.pop("allow_ctas", UNSET))

        def _parse_allow_cvas(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_cvas = _parse_allow_cvas(d.pop("allow_cvas", UNSET))

        def _parse_allow_dml(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_dml = _parse_allow_dml(d.pop("allow_dml", UNSET))

        def _parse_allow_file_upload(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_file_upload = _parse_allow_file_upload(d.pop("allow_file_upload", UNSET))

        def _parse_allow_run_async(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_run_async = _parse_allow_run_async(d.pop("allow_run_async", UNSET))

        backend = d.pop("backend", UNSET)

        def _parse_cache_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cache_timeout = _parse_cache_timeout(d.pop("cache_timeout", UNSET))

        def _parse_configuration_method(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        configuration_method = _parse_configuration_method(d.pop("configuration_method", UNSET))

        driver = d.pop("driver", UNSET)

        engine_information = d.pop("engine_information", UNSET)

        def _parse_expose_in_sqllab(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        expose_in_sqllab = _parse_expose_in_sqllab(d.pop("expose_in_sqllab", UNSET))

        def _parse_force_ctas_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        force_ctas_schema = _parse_force_ctas_schema(d.pop("force_ctas_schema", UNSET))

        id = d.pop("id", UNSET)

        def _parse_impersonate_user(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        impersonate_user = _parse_impersonate_user(d.pop("impersonate_user", UNSET))

        is_managed_externally = d.pop("is_managed_externally", UNSET)

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

        database_rest_api_get = cls(
            database_name=database_name,
            allow_ctas=allow_ctas,
            allow_cvas=allow_cvas,
            allow_dml=allow_dml,
            allow_file_upload=allow_file_upload,
            allow_run_async=allow_run_async,
            backend=backend,
            cache_timeout=cache_timeout,
            configuration_method=configuration_method,
            driver=driver,
            engine_information=engine_information,
            expose_in_sqllab=expose_in_sqllab,
            force_ctas_schema=force_ctas_schema,
            id=id,
            impersonate_user=impersonate_user,
            is_managed_externally=is_managed_externally,
            uuid=uuid,
        )

        database_rest_api_get.additional_properties = d
        return database_rest_api_get

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

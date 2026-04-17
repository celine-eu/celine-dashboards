from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.database_ssh_tunnel import DatabaseSSHTunnel
    from ..models.import_v1_database_extra import ImportV1DatabaseExtra


T = TypeVar("T", bound="ImportV1Database")


@_attrs_define
class ImportV1Database:
    """
    Attributes:
        database_name (str):
        sqlalchemy_uri (str):
        uuid (UUID):
        version (str):
        allow_csv_upload (bool | Unset):
        allow_ctas (bool | Unset):
        allow_cvas (bool | Unset):
        allow_dml (bool | Unset):
        allow_run_async (bool | Unset):
        cache_timeout (int | None | Unset):
        encrypted_extra (None | str | Unset):
        expose_in_sqllab (bool | Unset):
        external_url (None | str | Unset):
        extra (ImportV1DatabaseExtra | Unset):
        impersonate_user (bool | Unset):
        is_managed_externally (bool | None | Unset):
        password (None | str | Unset):
        ssh_tunnel (DatabaseSSHTunnel | None | Unset):
    """

    database_name: str
    sqlalchemy_uri: str
    uuid: UUID
    version: str
    allow_csv_upload: bool | Unset = UNSET
    allow_ctas: bool | Unset = UNSET
    allow_cvas: bool | Unset = UNSET
    allow_dml: bool | Unset = UNSET
    allow_run_async: bool | Unset = UNSET
    cache_timeout: int | None | Unset = UNSET
    encrypted_extra: None | str | Unset = UNSET
    expose_in_sqllab: bool | Unset = UNSET
    external_url: None | str | Unset = UNSET
    extra: ImportV1DatabaseExtra | Unset = UNSET
    impersonate_user: bool | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    password: None | str | Unset = UNSET
    ssh_tunnel: DatabaseSSHTunnel | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.database_ssh_tunnel import DatabaseSSHTunnel

        database_name = self.database_name

        sqlalchemy_uri = self.sqlalchemy_uri

        uuid = str(self.uuid)

        version = self.version

        allow_csv_upload = self.allow_csv_upload

        allow_ctas = self.allow_ctas

        allow_cvas = self.allow_cvas

        allow_dml = self.allow_dml

        allow_run_async = self.allow_run_async

        cache_timeout: int | None | Unset
        if isinstance(self.cache_timeout, Unset):
            cache_timeout = UNSET
        else:
            cache_timeout = self.cache_timeout

        encrypted_extra: None | str | Unset
        if isinstance(self.encrypted_extra, Unset):
            encrypted_extra = UNSET
        else:
            encrypted_extra = self.encrypted_extra

        expose_in_sqllab = self.expose_in_sqllab

        external_url: None | str | Unset
        if isinstance(self.external_url, Unset):
            external_url = UNSET
        else:
            external_url = self.external_url

        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        impersonate_user = self.impersonate_user

        is_managed_externally: bool | None | Unset
        if isinstance(self.is_managed_externally, Unset):
            is_managed_externally = UNSET
        else:
            is_managed_externally = self.is_managed_externally

        password: None | str | Unset
        if isinstance(self.password, Unset):
            password = UNSET
        else:
            password = self.password

        ssh_tunnel: dict[str, Any] | None | Unset
        if isinstance(self.ssh_tunnel, Unset):
            ssh_tunnel = UNSET
        elif isinstance(self.ssh_tunnel, DatabaseSSHTunnel):
            ssh_tunnel = self.ssh_tunnel.to_dict()
        else:
            ssh_tunnel = self.ssh_tunnel

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "database_name": database_name,
                "sqlalchemy_uri": sqlalchemy_uri,
                "uuid": uuid,
                "version": version,
            }
        )
        if allow_csv_upload is not UNSET:
            field_dict["allow_csv_upload"] = allow_csv_upload
        if allow_ctas is not UNSET:
            field_dict["allow_ctas"] = allow_ctas
        if allow_cvas is not UNSET:
            field_dict["allow_cvas"] = allow_cvas
        if allow_dml is not UNSET:
            field_dict["allow_dml"] = allow_dml
        if allow_run_async is not UNSET:
            field_dict["allow_run_async"] = allow_run_async
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if encrypted_extra is not UNSET:
            field_dict["encrypted_extra"] = encrypted_extra
        if expose_in_sqllab is not UNSET:
            field_dict["expose_in_sqllab"] = expose_in_sqllab
        if external_url is not UNSET:
            field_dict["external_url"] = external_url
        if extra is not UNSET:
            field_dict["extra"] = extra
        if impersonate_user is not UNSET:
            field_dict["impersonate_user"] = impersonate_user
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if password is not UNSET:
            field_dict["password"] = password
        if ssh_tunnel is not UNSET:
            field_dict["ssh_tunnel"] = ssh_tunnel

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.database_ssh_tunnel import DatabaseSSHTunnel
        from ..models.import_v1_database_extra import ImportV1DatabaseExtra

        d = dict(src_dict)
        database_name = d.pop("database_name")

        sqlalchemy_uri = d.pop("sqlalchemy_uri")

        uuid = UUID(d.pop("uuid"))

        version = d.pop("version")

        allow_csv_upload = d.pop("allow_csv_upload", UNSET)

        allow_ctas = d.pop("allow_ctas", UNSET)

        allow_cvas = d.pop("allow_cvas", UNSET)

        allow_dml = d.pop("allow_dml", UNSET)

        allow_run_async = d.pop("allow_run_async", UNSET)

        def _parse_cache_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cache_timeout = _parse_cache_timeout(d.pop("cache_timeout", UNSET))

        def _parse_encrypted_extra(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        encrypted_extra = _parse_encrypted_extra(d.pop("encrypted_extra", UNSET))

        expose_in_sqllab = d.pop("expose_in_sqllab", UNSET)

        def _parse_external_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        external_url = _parse_external_url(d.pop("external_url", UNSET))

        _extra = d.pop("extra", UNSET)
        extra: ImportV1DatabaseExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = ImportV1DatabaseExtra.from_dict(_extra)

        impersonate_user = d.pop("impersonate_user", UNSET)

        def _parse_is_managed_externally(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_managed_externally = _parse_is_managed_externally(d.pop("is_managed_externally", UNSET))

        def _parse_password(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        password = _parse_password(d.pop("password", UNSET))

        def _parse_ssh_tunnel(data: object) -> DatabaseSSHTunnel | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                ssh_tunnel_type_1 = DatabaseSSHTunnel.from_dict(data)

                return ssh_tunnel_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DatabaseSSHTunnel | None | Unset, data)

        ssh_tunnel = _parse_ssh_tunnel(d.pop("ssh_tunnel", UNSET))

        import_v1_database = cls(
            database_name=database_name,
            sqlalchemy_uri=sqlalchemy_uri,
            uuid=uuid,
            version=version,
            allow_csv_upload=allow_csv_upload,
            allow_ctas=allow_ctas,
            allow_cvas=allow_cvas,
            allow_dml=allow_dml,
            allow_run_async=allow_run_async,
            cache_timeout=cache_timeout,
            encrypted_extra=encrypted_extra,
            expose_in_sqllab=expose_in_sqllab,
            external_url=external_url,
            extra=extra,
            impersonate_user=impersonate_user,
            is_managed_externally=is_managed_externally,
            password=password,
            ssh_tunnel=ssh_tunnel,
        )

        import_v1_database.additional_properties = d
        return import_v1_database

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

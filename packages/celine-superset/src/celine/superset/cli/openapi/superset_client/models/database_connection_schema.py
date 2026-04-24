from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.database_connection_schema_parameters import DatabaseConnectionSchemaParameters
    from ..models.database_connection_schema_parameters_schema import DatabaseConnectionSchemaParametersSchema
    from ..models.database_ssh_tunnel import DatabaseSSHTunnel
    from ..models.engine_information import EngineInformation


T = TypeVar("T", bound="DatabaseConnectionSchema")


@_attrs_define
class DatabaseConnectionSchema:
    """
    Attributes:
        allow_ctas (bool | Unset): Allow CREATE TABLE AS option in SQL Lab
        allow_cvas (bool | Unset): Allow CREATE VIEW AS option in SQL Lab
        allow_dml (bool | Unset): Allow users to run non-SELECT statements (UPDATE, DELETE, CREATE, ...) in SQL Lab
        allow_file_upload (bool | Unset): Allow to upload CSV file data into this databaseIf selected, please set the
            schemas allowed for csv upload in Extra.
        allow_run_async (bool | Unset): Operate the database in asynchronous mode, meaning that the queries are executed
            on remote workers as opposed to on the web server itself. This assumes that you have a Celery worker setup as
            well as a results backend. Refer to the installation docs for more information.
        backend (None | str | Unset): SQLAlchemy engine to use
        cache_timeout (int | None | Unset): Duration (in seconds) of the caching timeout for charts of this database. A
            timeout of 0 indicates that the cache never expires. Note this defaults to the global timeout if undefined.
        configuration_method (str | Unset): Configuration_method is used on the frontend to inform the backend whether
            to explode parameters or to provide only a sqlalchemy_uri.
        database_name (None | str | Unset): A database name to identify this connection.
        driver (None | str | Unset): SQLAlchemy driver to use
        engine_information (EngineInformation | Unset):
        expose_in_sqllab (bool | Unset): Expose this database to SQLLab
        extra (str | Unset): <p>JSON string containing extra configuration elements.<br>1. The
            <code>engine_params</code> object gets unpacked into the <a
            href="https://docs.sqlalchemy.org/en/latest/core/engines.html#sqlalchemy.create_engine" rel="noopener
            noreferrer">sqlalchemy.create_engine</a> call, while the <code>metadata_params</code> gets unpacked into the <a
            href="https://docs.sqlalchemy.org/en/rel_1_0/core/metadata.html#sqlalchemy.schema.MetaData" rel="noopener
            noreferrer">sqlalchemy.MetaData</a> call.<br>2. The <code>metadata_cache_timeout</code> is a cache timeout
            setting in seconds for metadata fetch of this database. Specify it as <strong>"metadata_cache_timeout":
            {"schema_cache_timeout": 600, "table_cache_timeout": 600}</strong>. If unset, cache will not be enabled for the
            functionality. A timeout of 0 indicates that the cache never expires.<br>3. The
            <code>schemas_allowed_for_file_upload</code> is a comma separated list of schemas that CSVs are allowed to
            upload to. Specify it as <strong>"schemas_allowed_for_file_upload": ["public", "csv_upload"]</strong>. If
            database flavor does not support schema or any schema is allowed to be accessed, just leave the list empty<br>4.
            The <code>version</code> field is a string specifying the this db's version. This should be used with Presto DBs
            so that the syntax is correct<br>5. The <code>allows_virtual_table_explore</code> field is a boolean specifying
            whether or not the Explore button in SQL Lab results is shown.<br>6. The <code>disable_data_preview</code> field
            is a boolean specifying whether or not data preview queries will be run when fetching table metadata in SQL
            Lab.7. The <code>disable_drill_to_detail</code> field is a boolean specifying whether or notdrill to detail is
            disabled for the database.8. The <code>allow_multi_catalog</code> indicates if the database allows changing the
            default catalog when running queries and creating datasets.</p>
        force_ctas_schema (None | str | Unset): When allowing CREATE TABLE AS option in SQL Lab, this option forces the
            table to be created in this schema
        id (int | Unset): Database ID (for updates)
        impersonate_user (bool | Unset): If Presto, all the queries in SQL Lab are going to be executed as the currently
            logged on user who must have permission to run them.<br/>If Hive and hive.server2.enable.doAs is enabled, will
            run the queries as service account, but impersonate the currently logged on user via hive.server2.proxy.user
            property.
        is_managed_externally (bool | None | Unset):
        masked_encrypted_extra (None | str | Unset): <p>JSON string containing additional connection
            configuration.<br>This is used to provide connection information for systems like Hive, Presto, and BigQuery,
            which do not conform to the username:password syntax normally used by SQLAlchemy.</p>
        parameters (DatabaseConnectionSchemaParameters | Unset): DB-specific parameters for configuration
        parameters_schema (DatabaseConnectionSchemaParametersSchema | Unset): JSONSchema for configuring the database by
            parameters instead of SQLAlchemy URI
        server_cert (None | str | Unset): <p>Optional CA_BUNDLE contents to validate HTTPS requests. Only available on
            certain database engines.</p>
        sqlalchemy_uri (str | Unset): <p>Refer to the <a
            href="https://docs.sqlalchemy.org/en/rel_1_2/core/engines.html#database-urls" rel="noopener
            noreferrer">SqlAlchemy docs</a> for more information on how to structure your URI.</p>
        ssh_tunnel (DatabaseSSHTunnel | None | Unset):
        uuid (str | Unset):
    """

    allow_ctas: bool | Unset = UNSET
    allow_cvas: bool | Unset = UNSET
    allow_dml: bool | Unset = UNSET
    allow_file_upload: bool | Unset = UNSET
    allow_run_async: bool | Unset = UNSET
    backend: None | str | Unset = UNSET
    cache_timeout: int | None | Unset = UNSET
    configuration_method: str | Unset = UNSET
    database_name: None | str | Unset = UNSET
    driver: None | str | Unset = UNSET
    engine_information: EngineInformation | Unset = UNSET
    expose_in_sqllab: bool | Unset = UNSET
    extra: str | Unset = UNSET
    force_ctas_schema: None | str | Unset = UNSET
    id: int | Unset = UNSET
    impersonate_user: bool | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    masked_encrypted_extra: None | str | Unset = UNSET
    parameters: DatabaseConnectionSchemaParameters | Unset = UNSET
    parameters_schema: DatabaseConnectionSchemaParametersSchema | Unset = UNSET
    server_cert: None | str | Unset = UNSET
    sqlalchemy_uri: str | Unset = UNSET
    ssh_tunnel: DatabaseSSHTunnel | None | Unset = UNSET
    uuid: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.database_ssh_tunnel import DatabaseSSHTunnel

        allow_ctas = self.allow_ctas

        allow_cvas = self.allow_cvas

        allow_dml = self.allow_dml

        allow_file_upload = self.allow_file_upload

        allow_run_async = self.allow_run_async

        backend: None | str | Unset
        if isinstance(self.backend, Unset):
            backend = UNSET
        else:
            backend = self.backend

        cache_timeout: int | None | Unset
        if isinstance(self.cache_timeout, Unset):
            cache_timeout = UNSET
        else:
            cache_timeout = self.cache_timeout

        configuration_method = self.configuration_method

        database_name: None | str | Unset
        if isinstance(self.database_name, Unset):
            database_name = UNSET
        else:
            database_name = self.database_name

        driver: None | str | Unset
        if isinstance(self.driver, Unset):
            driver = UNSET
        else:
            driver = self.driver

        engine_information: dict[str, Any] | Unset = UNSET
        if not isinstance(self.engine_information, Unset):
            engine_information = self.engine_information.to_dict()

        expose_in_sqllab = self.expose_in_sqllab

        extra = self.extra

        force_ctas_schema: None | str | Unset
        if isinstance(self.force_ctas_schema, Unset):
            force_ctas_schema = UNSET
        else:
            force_ctas_schema = self.force_ctas_schema

        id = self.id

        impersonate_user = self.impersonate_user

        is_managed_externally: bool | None | Unset
        if isinstance(self.is_managed_externally, Unset):
            is_managed_externally = UNSET
        else:
            is_managed_externally = self.is_managed_externally

        masked_encrypted_extra: None | str | Unset
        if isinstance(self.masked_encrypted_extra, Unset):
            masked_encrypted_extra = UNSET
        else:
            masked_encrypted_extra = self.masked_encrypted_extra

        parameters: dict[str, Any] | Unset = UNSET
        if not isinstance(self.parameters, Unset):
            parameters = self.parameters.to_dict()

        parameters_schema: dict[str, Any] | Unset = UNSET
        if not isinstance(self.parameters_schema, Unset):
            parameters_schema = self.parameters_schema.to_dict()

        server_cert: None | str | Unset
        if isinstance(self.server_cert, Unset):
            server_cert = UNSET
        else:
            server_cert = self.server_cert

        sqlalchemy_uri = self.sqlalchemy_uri

        ssh_tunnel: dict[str, Any] | None | Unset
        if isinstance(self.ssh_tunnel, Unset):
            ssh_tunnel = UNSET
        elif isinstance(self.ssh_tunnel, DatabaseSSHTunnel):
            ssh_tunnel = self.ssh_tunnel.to_dict()
        else:
            ssh_tunnel = self.ssh_tunnel

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
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
        if database_name is not UNSET:
            field_dict["database_name"] = database_name
        if driver is not UNSET:
            field_dict["driver"] = driver
        if engine_information is not UNSET:
            field_dict["engine_information"] = engine_information
        if expose_in_sqllab is not UNSET:
            field_dict["expose_in_sqllab"] = expose_in_sqllab
        if extra is not UNSET:
            field_dict["extra"] = extra
        if force_ctas_schema is not UNSET:
            field_dict["force_ctas_schema"] = force_ctas_schema
        if id is not UNSET:
            field_dict["id"] = id
        if impersonate_user is not UNSET:
            field_dict["impersonate_user"] = impersonate_user
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if masked_encrypted_extra is not UNSET:
            field_dict["masked_encrypted_extra"] = masked_encrypted_extra
        if parameters is not UNSET:
            field_dict["parameters"] = parameters
        if parameters_schema is not UNSET:
            field_dict["parameters_schema"] = parameters_schema
        if server_cert is not UNSET:
            field_dict["server_cert"] = server_cert
        if sqlalchemy_uri is not UNSET:
            field_dict["sqlalchemy_uri"] = sqlalchemy_uri
        if ssh_tunnel is not UNSET:
            field_dict["ssh_tunnel"] = ssh_tunnel
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.database_connection_schema_parameters import DatabaseConnectionSchemaParameters
        from ..models.database_connection_schema_parameters_schema import DatabaseConnectionSchemaParametersSchema
        from ..models.database_ssh_tunnel import DatabaseSSHTunnel
        from ..models.engine_information import EngineInformation

        d = dict(src_dict)
        allow_ctas = d.pop("allow_ctas", UNSET)

        allow_cvas = d.pop("allow_cvas", UNSET)

        allow_dml = d.pop("allow_dml", UNSET)

        allow_file_upload = d.pop("allow_file_upload", UNSET)

        allow_run_async = d.pop("allow_run_async", UNSET)

        def _parse_backend(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        backend = _parse_backend(d.pop("backend", UNSET))

        def _parse_cache_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cache_timeout = _parse_cache_timeout(d.pop("cache_timeout", UNSET))

        configuration_method = d.pop("configuration_method", UNSET)

        def _parse_database_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        database_name = _parse_database_name(d.pop("database_name", UNSET))

        def _parse_driver(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        driver = _parse_driver(d.pop("driver", UNSET))

        _engine_information = d.pop("engine_information", UNSET)
        engine_information: EngineInformation | Unset
        if isinstance(_engine_information, Unset):
            engine_information = UNSET
        else:
            engine_information = EngineInformation.from_dict(_engine_information)

        expose_in_sqllab = d.pop("expose_in_sqllab", UNSET)

        extra = d.pop("extra", UNSET)

        def _parse_force_ctas_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        force_ctas_schema = _parse_force_ctas_schema(d.pop("force_ctas_schema", UNSET))

        id = d.pop("id", UNSET)

        impersonate_user = d.pop("impersonate_user", UNSET)

        def _parse_is_managed_externally(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_managed_externally = _parse_is_managed_externally(d.pop("is_managed_externally", UNSET))

        def _parse_masked_encrypted_extra(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        masked_encrypted_extra = _parse_masked_encrypted_extra(d.pop("masked_encrypted_extra", UNSET))

        _parameters = d.pop("parameters", UNSET)
        parameters: DatabaseConnectionSchemaParameters | Unset
        if isinstance(_parameters, Unset):
            parameters = UNSET
        else:
            parameters = DatabaseConnectionSchemaParameters.from_dict(_parameters)

        _parameters_schema = d.pop("parameters_schema", UNSET)
        parameters_schema: DatabaseConnectionSchemaParametersSchema | Unset
        if isinstance(_parameters_schema, Unset):
            parameters_schema = UNSET
        else:
            parameters_schema = DatabaseConnectionSchemaParametersSchema.from_dict(_parameters_schema)

        def _parse_server_cert(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        server_cert = _parse_server_cert(d.pop("server_cert", UNSET))

        sqlalchemy_uri = d.pop("sqlalchemy_uri", UNSET)

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

        uuid = d.pop("uuid", UNSET)

        database_connection_schema = cls(
            allow_ctas=allow_ctas,
            allow_cvas=allow_cvas,
            allow_dml=allow_dml,
            allow_file_upload=allow_file_upload,
            allow_run_async=allow_run_async,
            backend=backend,
            cache_timeout=cache_timeout,
            configuration_method=configuration_method,
            database_name=database_name,
            driver=driver,
            engine_information=engine_information,
            expose_in_sqllab=expose_in_sqllab,
            extra=extra,
            force_ctas_schema=force_ctas_schema,
            id=id,
            impersonate_user=impersonate_user,
            is_managed_externally=is_managed_externally,
            masked_encrypted_extra=masked_encrypted_extra,
            parameters=parameters,
            parameters_schema=parameters_schema,
            server_cert=server_cert,
            sqlalchemy_uri=sqlalchemy_uri,
            ssh_tunnel=ssh_tunnel,
            uuid=uuid,
        )

        database_connection_schema.additional_properties = d
        return database_connection_schema

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

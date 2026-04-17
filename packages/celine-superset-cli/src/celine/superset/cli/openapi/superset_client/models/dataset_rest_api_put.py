from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_columns_put import DatasetColumnsPut
    from ..models.dataset_metrics_put import DatasetMetricsPut
    from ..models.folder import Folder


T = TypeVar("T", bound="DatasetRestApiPut")


@_attrs_define
class DatasetRestApiPut:
    """
    Attributes:
        always_filter_main_dttm (bool | Unset):  Default: False.
        cache_timeout (int | None | Unset):
        catalog (None | str | Unset):
        columns (list[DatasetColumnsPut] | Unset):
        database_id (int | Unset):
        default_endpoint (None | str | Unset):
        description (None | str | Unset):
        external_url (None | str | Unset):
        extra (None | str | Unset):
        fetch_values_predicate (None | str | Unset):
        filter_select_enabled (bool | None | Unset):
        folders (list[Folder] | Unset):
        is_managed_externally (bool | None | Unset):
        is_sqllab_view (bool | None | Unset):
        main_dttm_col (None | str | Unset):
        metrics (list[DatasetMetricsPut] | Unset):
        normalize_columns (bool | None | Unset):
        offset (int | None | Unset):
        owners (list[int] | Unset):
        schema (None | str | Unset):
        sql (None | str | Unset):
        table_name (None | str | Unset):
        template_params (None | str | Unset):
        uuid (None | Unset | UUID):
    """

    always_filter_main_dttm: bool | Unset = False
    cache_timeout: int | None | Unset = UNSET
    catalog: None | str | Unset = UNSET
    columns: list[DatasetColumnsPut] | Unset = UNSET
    database_id: int | Unset = UNSET
    default_endpoint: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    external_url: None | str | Unset = UNSET
    extra: None | str | Unset = UNSET
    fetch_values_predicate: None | str | Unset = UNSET
    filter_select_enabled: bool | None | Unset = UNSET
    folders: list[Folder] | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    is_sqllab_view: bool | None | Unset = UNSET
    main_dttm_col: None | str | Unset = UNSET
    metrics: list[DatasetMetricsPut] | Unset = UNSET
    normalize_columns: bool | None | Unset = UNSET
    offset: int | None | Unset = UNSET
    owners: list[int] | Unset = UNSET
    schema: None | str | Unset = UNSET
    sql: None | str | Unset = UNSET
    table_name: None | str | Unset = UNSET
    template_params: None | str | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        always_filter_main_dttm = self.always_filter_main_dttm

        cache_timeout: int | None | Unset
        if isinstance(self.cache_timeout, Unset):
            cache_timeout = UNSET
        else:
            cache_timeout = self.cache_timeout

        catalog: None | str | Unset
        if isinstance(self.catalog, Unset):
            catalog = UNSET
        else:
            catalog = self.catalog

        columns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = []
            for columns_item_data in self.columns:
                columns_item = columns_item_data.to_dict()
                columns.append(columns_item)

        database_id = self.database_id

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

        external_url: None | str | Unset
        if isinstance(self.external_url, Unset):
            external_url = UNSET
        else:
            external_url = self.external_url

        extra: None | str | Unset
        if isinstance(self.extra, Unset):
            extra = UNSET
        else:
            extra = self.extra

        fetch_values_predicate: None | str | Unset
        if isinstance(self.fetch_values_predicate, Unset):
            fetch_values_predicate = UNSET
        else:
            fetch_values_predicate = self.fetch_values_predicate

        filter_select_enabled: bool | None | Unset
        if isinstance(self.filter_select_enabled, Unset):
            filter_select_enabled = UNSET
        else:
            filter_select_enabled = self.filter_select_enabled

        folders: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.folders, Unset):
            folders = []
            for folders_item_data in self.folders:
                folders_item = folders_item_data.to_dict()
                folders.append(folders_item)

        is_managed_externally: bool | None | Unset
        if isinstance(self.is_managed_externally, Unset):
            is_managed_externally = UNSET
        else:
            is_managed_externally = self.is_managed_externally

        is_sqllab_view: bool | None | Unset
        if isinstance(self.is_sqllab_view, Unset):
            is_sqllab_view = UNSET
        else:
            is_sqllab_view = self.is_sqllab_view

        main_dttm_col: None | str | Unset
        if isinstance(self.main_dttm_col, Unset):
            main_dttm_col = UNSET
        else:
            main_dttm_col = self.main_dttm_col

        metrics: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.metrics, Unset):
            metrics = []
            for metrics_item_data in self.metrics:
                metrics_item = metrics_item_data.to_dict()
                metrics.append(metrics_item)

        normalize_columns: bool | None | Unset
        if isinstance(self.normalize_columns, Unset):
            normalize_columns = UNSET
        else:
            normalize_columns = self.normalize_columns

        offset: int | None | Unset
        if isinstance(self.offset, Unset):
            offset = UNSET
        else:
            offset = self.offset

        owners: list[int] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners

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

        table_name: None | str | Unset
        if isinstance(self.table_name, Unset):
            table_name = UNSET
        else:
            table_name = self.table_name

        template_params: None | str | Unset
        if isinstance(self.template_params, Unset):
            template_params = UNSET
        else:
            template_params = self.template_params

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if always_filter_main_dttm is not UNSET:
            field_dict["always_filter_main_dttm"] = always_filter_main_dttm
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if columns is not UNSET:
            field_dict["columns"] = columns
        if database_id is not UNSET:
            field_dict["database_id"] = database_id
        if default_endpoint is not UNSET:
            field_dict["default_endpoint"] = default_endpoint
        if description is not UNSET:
            field_dict["description"] = description
        if external_url is not UNSET:
            field_dict["external_url"] = external_url
        if extra is not UNSET:
            field_dict["extra"] = extra
        if fetch_values_predicate is not UNSET:
            field_dict["fetch_values_predicate"] = fetch_values_predicate
        if filter_select_enabled is not UNSET:
            field_dict["filter_select_enabled"] = filter_select_enabled
        if folders is not UNSET:
            field_dict["folders"] = folders
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if is_sqllab_view is not UNSET:
            field_dict["is_sqllab_view"] = is_sqllab_view
        if main_dttm_col is not UNSET:
            field_dict["main_dttm_col"] = main_dttm_col
        if metrics is not UNSET:
            field_dict["metrics"] = metrics
        if normalize_columns is not UNSET:
            field_dict["normalize_columns"] = normalize_columns
        if offset is not UNSET:
            field_dict["offset"] = offset
        if owners is not UNSET:
            field_dict["owners"] = owners
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sql is not UNSET:
            field_dict["sql"] = sql
        if table_name is not UNSET:
            field_dict["table_name"] = table_name
        if template_params is not UNSET:
            field_dict["template_params"] = template_params
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset_columns_put import DatasetColumnsPut
        from ..models.dataset_metrics_put import DatasetMetricsPut
        from ..models.folder import Folder

        d = dict(src_dict)
        always_filter_main_dttm = d.pop("always_filter_main_dttm", UNSET)

        def _parse_cache_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cache_timeout = _parse_cache_timeout(d.pop("cache_timeout", UNSET))

        def _parse_catalog(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        catalog = _parse_catalog(d.pop("catalog", UNSET))

        _columns = d.pop("columns", UNSET)
        columns: list[DatasetColumnsPut] | Unset = UNSET
        if _columns is not UNSET:
            columns = []
            for columns_item_data in _columns:
                columns_item = DatasetColumnsPut.from_dict(columns_item_data)

                columns.append(columns_item)

        database_id = d.pop("database_id", UNSET)

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

        def _parse_external_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        external_url = _parse_external_url(d.pop("external_url", UNSET))

        def _parse_extra(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extra = _parse_extra(d.pop("extra", UNSET))

        def _parse_fetch_values_predicate(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fetch_values_predicate = _parse_fetch_values_predicate(d.pop("fetch_values_predicate", UNSET))

        def _parse_filter_select_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        filter_select_enabled = _parse_filter_select_enabled(d.pop("filter_select_enabled", UNSET))

        _folders = d.pop("folders", UNSET)
        folders: list[Folder] | Unset = UNSET
        if _folders is not UNSET:
            folders = []
            for folders_item_data in _folders:
                folders_item = Folder.from_dict(folders_item_data)

                folders.append(folders_item)

        def _parse_is_managed_externally(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_managed_externally = _parse_is_managed_externally(d.pop("is_managed_externally", UNSET))

        def _parse_is_sqllab_view(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_sqllab_view = _parse_is_sqllab_view(d.pop("is_sqllab_view", UNSET))

        def _parse_main_dttm_col(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        main_dttm_col = _parse_main_dttm_col(d.pop("main_dttm_col", UNSET))

        _metrics = d.pop("metrics", UNSET)
        metrics: list[DatasetMetricsPut] | Unset = UNSET
        if _metrics is not UNSET:
            metrics = []
            for metrics_item_data in _metrics:
                metrics_item = DatasetMetricsPut.from_dict(metrics_item_data)

                metrics.append(metrics_item)

        def _parse_normalize_columns(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        normalize_columns = _parse_normalize_columns(d.pop("normalize_columns", UNSET))

        def _parse_offset(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        offset = _parse_offset(d.pop("offset", UNSET))

        owners = cast(list[int], d.pop("owners", UNSET))

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

        def _parse_table_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        table_name = _parse_table_name(d.pop("table_name", UNSET))

        def _parse_template_params(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_params = _parse_template_params(d.pop("template_params", UNSET))

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

        dataset_rest_api_put = cls(
            always_filter_main_dttm=always_filter_main_dttm,
            cache_timeout=cache_timeout,
            catalog=catalog,
            columns=columns,
            database_id=database_id,
            default_endpoint=default_endpoint,
            description=description,
            external_url=external_url,
            extra=extra,
            fetch_values_predicate=fetch_values_predicate,
            filter_select_enabled=filter_select_enabled,
            folders=folders,
            is_managed_externally=is_managed_externally,
            is_sqllab_view=is_sqllab_view,
            main_dttm_col=main_dttm_col,
            metrics=metrics,
            normalize_columns=normalize_columns,
            offset=offset,
            owners=owners,
            schema=schema,
            sql=sql,
            table_name=table_name,
            template_params=template_params,
            uuid=uuid,
        )

        dataset_rest_api_put.additional_properties = d
        return dataset_rest_api_put

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

from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_rest_api_get_database import DatasetRestApiGetDatabase
    from ..models.dataset_rest_api_get_sql_metric import DatasetRestApiGetSqlMetric
    from ..models.dataset_rest_api_get_table_column import DatasetRestApiGetTableColumn
    from ..models.dataset_rest_api_get_user import DatasetRestApiGetUser
    from ..models.dataset_rest_api_get_user_1 import DatasetRestApiGetUser1
    from ..models.dataset_rest_api_get_user_2 import DatasetRestApiGetUser2


T = TypeVar("T", bound="DatasetRestApiGet")


@_attrs_define
class DatasetRestApiGet:
    """
    Attributes:
        columns (DatasetRestApiGetTableColumn):
        database (DatasetRestApiGetDatabase):
        metrics (DatasetRestApiGetSqlMetric):
        table_name (str):
        always_filter_main_dttm (bool | None | Unset):
        cache_timeout (int | None | Unset):
        catalog (None | str | Unset):
        changed_by (DatasetRestApiGetUser2 | Unset):
        changed_on (datetime.datetime | None | Unset):
        changed_on_humanized (Any | Unset):
        column_formats (Any | Unset):
        created_by (DatasetRestApiGetUser1 | Unset):
        created_on (datetime.datetime | None | Unset):
        created_on_humanized (Any | Unset):
        datasource_name (Any | Unset):
        datasource_type (Any | Unset):
        default_endpoint (None | str | Unset):
        description (None | str | Unset):
        extra (None | str | Unset):
        fetch_values_predicate (None | str | Unset):
        filter_select_enabled (bool | None | Unset):
        folders (Any | Unset):
        granularity_sqla (Any | Unset):
        id (int | Unset):
        is_managed_externally (bool | Unset):
        is_sqllab_view (bool | None | Unset):
        kind (Any | Unset):
        main_dttm_col (None | str | Unset):
        name (Any | Unset):
        normalize_columns (bool | None | Unset):
        offset (int | None | Unset):
        order_by_choices (Any | Unset):
        owners (DatasetRestApiGetUser | Unset):
        schema (None | str | Unset):
        select_star (Any | Unset):
        sql (None | str | Unset):
        template_params (None | str | Unset):
        time_grain_sqla (Any | Unset):
        uid (Any | Unset):
        url (Any | Unset):
        uuid (None | Unset | UUID):
        verbose_map (Any | Unset):
    """

    columns: DatasetRestApiGetTableColumn
    database: DatasetRestApiGetDatabase
    metrics: DatasetRestApiGetSqlMetric
    table_name: str
    always_filter_main_dttm: bool | None | Unset = UNSET
    cache_timeout: int | None | Unset = UNSET
    catalog: None | str | Unset = UNSET
    changed_by: DatasetRestApiGetUser2 | Unset = UNSET
    changed_on: datetime.datetime | None | Unset = UNSET
    changed_on_humanized: Any | Unset = UNSET
    column_formats: Any | Unset = UNSET
    created_by: DatasetRestApiGetUser1 | Unset = UNSET
    created_on: datetime.datetime | None | Unset = UNSET
    created_on_humanized: Any | Unset = UNSET
    datasource_name: Any | Unset = UNSET
    datasource_type: Any | Unset = UNSET
    default_endpoint: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    extra: None | str | Unset = UNSET
    fetch_values_predicate: None | str | Unset = UNSET
    filter_select_enabled: bool | None | Unset = UNSET
    folders: Any | Unset = UNSET
    granularity_sqla: Any | Unset = UNSET
    id: int | Unset = UNSET
    is_managed_externally: bool | Unset = UNSET
    is_sqllab_view: bool | None | Unset = UNSET
    kind: Any | Unset = UNSET
    main_dttm_col: None | str | Unset = UNSET
    name: Any | Unset = UNSET
    normalize_columns: bool | None | Unset = UNSET
    offset: int | None | Unset = UNSET
    order_by_choices: Any | Unset = UNSET
    owners: DatasetRestApiGetUser | Unset = UNSET
    schema: None | str | Unset = UNSET
    select_star: Any | Unset = UNSET
    sql: None | str | Unset = UNSET
    template_params: None | str | Unset = UNSET
    time_grain_sqla: Any | Unset = UNSET
    uid: Any | Unset = UNSET
    url: Any | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    verbose_map: Any | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        columns = self.columns.to_dict()

        database = self.database.to_dict()

        metrics = self.metrics.to_dict()

        table_name = self.table_name

        always_filter_main_dttm: bool | None | Unset
        if isinstance(self.always_filter_main_dttm, Unset):
            always_filter_main_dttm = UNSET
        else:
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

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        changed_on_humanized = self.changed_on_humanized

        column_formats = self.column_formats

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on: None | str | Unset
        if isinstance(self.created_on, Unset):
            created_on = UNSET
        elif isinstance(self.created_on, datetime.datetime):
            created_on = self.created_on.isoformat()
        else:
            created_on = self.created_on

        created_on_humanized = self.created_on_humanized

        datasource_name = self.datasource_name

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

        folders = self.folders

        granularity_sqla = self.granularity_sqla

        id = self.id

        is_managed_externally = self.is_managed_externally

        is_sqllab_view: bool | None | Unset
        if isinstance(self.is_sqllab_view, Unset):
            is_sqllab_view = UNSET
        else:
            is_sqllab_view = self.is_sqllab_view

        kind = self.kind

        main_dttm_col: None | str | Unset
        if isinstance(self.main_dttm_col, Unset):
            main_dttm_col = UNSET
        else:
            main_dttm_col = self.main_dttm_col

        name = self.name

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

        order_by_choices = self.order_by_choices

        owners: dict[str, Any] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners.to_dict()

        schema: None | str | Unset
        if isinstance(self.schema, Unset):
            schema = UNSET
        else:
            schema = self.schema

        select_star = self.select_star

        sql: None | str | Unset
        if isinstance(self.sql, Unset):
            sql = UNSET
        else:
            sql = self.sql

        template_params: None | str | Unset
        if isinstance(self.template_params, Unset):
            template_params = UNSET
        else:
            template_params = self.template_params

        time_grain_sqla = self.time_grain_sqla

        uid = self.uid

        url = self.url

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        verbose_map = self.verbose_map

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "columns": columns,
                "database": database,
                "metrics": metrics,
                "table_name": table_name,
            }
        )
        if always_filter_main_dttm is not UNSET:
            field_dict["always_filter_main_dttm"] = always_filter_main_dttm
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if catalog is not UNSET:
            field_dict["catalog"] = catalog
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if changed_on_humanized is not UNSET:
            field_dict["changed_on_humanized"] = changed_on_humanized
        if column_formats is not UNSET:
            field_dict["column_formats"] = column_formats
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on is not UNSET:
            field_dict["created_on"] = created_on
        if created_on_humanized is not UNSET:
            field_dict["created_on_humanized"] = created_on_humanized
        if datasource_name is not UNSET:
            field_dict["datasource_name"] = datasource_name
        if datasource_type is not UNSET:
            field_dict["datasource_type"] = datasource_type
        if default_endpoint is not UNSET:
            field_dict["default_endpoint"] = default_endpoint
        if description is not UNSET:
            field_dict["description"] = description
        if extra is not UNSET:
            field_dict["extra"] = extra
        if fetch_values_predicate is not UNSET:
            field_dict["fetch_values_predicate"] = fetch_values_predicate
        if filter_select_enabled is not UNSET:
            field_dict["filter_select_enabled"] = filter_select_enabled
        if folders is not UNSET:
            field_dict["folders"] = folders
        if granularity_sqla is not UNSET:
            field_dict["granularity_sqla"] = granularity_sqla
        if id is not UNSET:
            field_dict["id"] = id
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if is_sqllab_view is not UNSET:
            field_dict["is_sqllab_view"] = is_sqllab_view
        if kind is not UNSET:
            field_dict["kind"] = kind
        if main_dttm_col is not UNSET:
            field_dict["main_dttm_col"] = main_dttm_col
        if name is not UNSET:
            field_dict["name"] = name
        if normalize_columns is not UNSET:
            field_dict["normalize_columns"] = normalize_columns
        if offset is not UNSET:
            field_dict["offset"] = offset
        if order_by_choices is not UNSET:
            field_dict["order_by_choices"] = order_by_choices
        if owners is not UNSET:
            field_dict["owners"] = owners
        if schema is not UNSET:
            field_dict["schema"] = schema
        if select_star is not UNSET:
            field_dict["select_star"] = select_star
        if sql is not UNSET:
            field_dict["sql"] = sql
        if template_params is not UNSET:
            field_dict["template_params"] = template_params
        if time_grain_sqla is not UNSET:
            field_dict["time_grain_sqla"] = time_grain_sqla
        if uid is not UNSET:
            field_dict["uid"] = uid
        if url is not UNSET:
            field_dict["url"] = url
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if verbose_map is not UNSET:
            field_dict["verbose_map"] = verbose_map

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset_rest_api_get_database import DatasetRestApiGetDatabase
        from ..models.dataset_rest_api_get_sql_metric import DatasetRestApiGetSqlMetric
        from ..models.dataset_rest_api_get_table_column import DatasetRestApiGetTableColumn
        from ..models.dataset_rest_api_get_user import DatasetRestApiGetUser
        from ..models.dataset_rest_api_get_user_1 import DatasetRestApiGetUser1
        from ..models.dataset_rest_api_get_user_2 import DatasetRestApiGetUser2

        d = dict(src_dict)
        columns = DatasetRestApiGetTableColumn.from_dict(d.pop("columns"))

        database = DatasetRestApiGetDatabase.from_dict(d.pop("database"))

        metrics = DatasetRestApiGetSqlMetric.from_dict(d.pop("metrics"))

        table_name = d.pop("table_name")

        def _parse_always_filter_main_dttm(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        always_filter_main_dttm = _parse_always_filter_main_dttm(d.pop("always_filter_main_dttm", UNSET))

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

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: DatasetRestApiGetUser2 | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = DatasetRestApiGetUser2.from_dict(_changed_by)

        def _parse_changed_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                changed_on_type_0 = isoparse(data)

                return changed_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        changed_on = _parse_changed_on(d.pop("changed_on", UNSET))

        changed_on_humanized = d.pop("changed_on_humanized", UNSET)

        column_formats = d.pop("column_formats", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: DatasetRestApiGetUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = DatasetRestApiGetUser1.from_dict(_created_by)

        def _parse_created_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                created_on_type_0 = isoparse(data)

                return created_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        created_on = _parse_created_on(d.pop("created_on", UNSET))

        created_on_humanized = d.pop("created_on_humanized", UNSET)

        datasource_name = d.pop("datasource_name", UNSET)

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

        folders = d.pop("folders", UNSET)

        granularity_sqla = d.pop("granularity_sqla", UNSET)

        id = d.pop("id", UNSET)

        is_managed_externally = d.pop("is_managed_externally", UNSET)

        def _parse_is_sqllab_view(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_sqllab_view = _parse_is_sqllab_view(d.pop("is_sqllab_view", UNSET))

        kind = d.pop("kind", UNSET)

        def _parse_main_dttm_col(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        main_dttm_col = _parse_main_dttm_col(d.pop("main_dttm_col", UNSET))

        name = d.pop("name", UNSET)

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

        order_by_choices = d.pop("order_by_choices", UNSET)

        _owners = d.pop("owners", UNSET)
        owners: DatasetRestApiGetUser | Unset
        if isinstance(_owners, Unset):
            owners = UNSET
        else:
            owners = DatasetRestApiGetUser.from_dict(_owners)

        def _parse_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schema = _parse_schema(d.pop("schema", UNSET))

        select_star = d.pop("select_star", UNSET)

        def _parse_sql(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sql = _parse_sql(d.pop("sql", UNSET))

        def _parse_template_params(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_params = _parse_template_params(d.pop("template_params", UNSET))

        time_grain_sqla = d.pop("time_grain_sqla", UNSET)

        uid = d.pop("uid", UNSET)

        url = d.pop("url", UNSET)

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

        verbose_map = d.pop("verbose_map", UNSET)

        dataset_rest_api_get = cls(
            columns=columns,
            database=database,
            metrics=metrics,
            table_name=table_name,
            always_filter_main_dttm=always_filter_main_dttm,
            cache_timeout=cache_timeout,
            catalog=catalog,
            changed_by=changed_by,
            changed_on=changed_on,
            changed_on_humanized=changed_on_humanized,
            column_formats=column_formats,
            created_by=created_by,
            created_on=created_on,
            created_on_humanized=created_on_humanized,
            datasource_name=datasource_name,
            datasource_type=datasource_type,
            default_endpoint=default_endpoint,
            description=description,
            extra=extra,
            fetch_values_predicate=fetch_values_predicate,
            filter_select_enabled=filter_select_enabled,
            folders=folders,
            granularity_sqla=granularity_sqla,
            id=id,
            is_managed_externally=is_managed_externally,
            is_sqllab_view=is_sqllab_view,
            kind=kind,
            main_dttm_col=main_dttm_col,
            name=name,
            normalize_columns=normalize_columns,
            offset=offset,
            order_by_choices=order_by_choices,
            owners=owners,
            schema=schema,
            select_star=select_star,
            sql=sql,
            template_params=template_params,
            time_grain_sqla=time_grain_sqla,
            uid=uid,
            url=url,
            uuid=uuid,
            verbose_map=verbose_map,
        )

        dataset_rest_api_get.additional_properties = d
        return dataset_rest_api_get

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

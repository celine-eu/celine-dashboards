from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dashboard_dataset_schema_column_formats import DashboardDatasetSchemaColumnFormats
    from ..models.dashboard_dataset_schema_columns_item import DashboardDatasetSchemaColumnsItem
    from ..models.dashboard_dataset_schema_metrics_item import DashboardDatasetSchemaMetricsItem
    from ..models.dashboard_dataset_schema_owners_item import DashboardDatasetSchemaOwnersItem
    from ..models.dashboard_dataset_schema_verbose_map import DashboardDatasetSchemaVerboseMap
    from ..models.database import Database


T = TypeVar("T", bound="DashboardDatasetSchema")


@_attrs_define
class DashboardDatasetSchema:
    """
    Attributes:
        always_filter_main_dttm (bool | Unset):
        cache_timeout (int | Unset):
        column_formats (DashboardDatasetSchemaColumnFormats | Unset):
        column_names (list[str] | Unset):
        column_types (list[int] | Unset):
        columns (list[DashboardDatasetSchemaColumnsItem] | Unset):
        database (Database | Unset):
        datasource_name (str | Unset):
        default_endpoint (str | Unset):
        edit_url (str | Unset):
        fetch_values_predicate (str | Unset):
        filter_select (bool | Unset):
        filter_select_enabled (bool | Unset):
        granularity_sqla (list[list[str]] | Unset):
        health_check_message (str | Unset):
        id (int | Unset):
        is_sqllab_view (bool | Unset):
        main_dttm_col (str | Unset):
        metrics (list[DashboardDatasetSchemaMetricsItem] | Unset):
        name (str | Unset):
        normalize_columns (bool | Unset):
        offset (int | Unset):
        order_by_choices (list[list[str]] | Unset):
        owners (list[DashboardDatasetSchemaOwnersItem] | Unset):
        params (str | Unset):
        perm (str | Unset):
        schema (str | Unset):
        select_star (str | Unset):
        sql (str | Unset):
        table_name (str | Unset):
        template_params (str | Unset):
        time_grain_sqla (list[list[str]] | Unset):
        type_ (str | Unset):
        uid (str | Unset):
        verbose_map (DashboardDatasetSchemaVerboseMap | Unset):
    """

    always_filter_main_dttm: bool | Unset = UNSET
    cache_timeout: int | Unset = UNSET
    column_formats: DashboardDatasetSchemaColumnFormats | Unset = UNSET
    column_names: list[str] | Unset = UNSET
    column_types: list[int] | Unset = UNSET
    columns: list[DashboardDatasetSchemaColumnsItem] | Unset = UNSET
    database: Database | Unset = UNSET
    datasource_name: str | Unset = UNSET
    default_endpoint: str | Unset = UNSET
    edit_url: str | Unset = UNSET
    fetch_values_predicate: str | Unset = UNSET
    filter_select: bool | Unset = UNSET
    filter_select_enabled: bool | Unset = UNSET
    granularity_sqla: list[list[str]] | Unset = UNSET
    health_check_message: str | Unset = UNSET
    id: int | Unset = UNSET
    is_sqllab_view: bool | Unset = UNSET
    main_dttm_col: str | Unset = UNSET
    metrics: list[DashboardDatasetSchemaMetricsItem] | Unset = UNSET
    name: str | Unset = UNSET
    normalize_columns: bool | Unset = UNSET
    offset: int | Unset = UNSET
    order_by_choices: list[list[str]] | Unset = UNSET
    owners: list[DashboardDatasetSchemaOwnersItem] | Unset = UNSET
    params: str | Unset = UNSET
    perm: str | Unset = UNSET
    schema: str | Unset = UNSET
    select_star: str | Unset = UNSET
    sql: str | Unset = UNSET
    table_name: str | Unset = UNSET
    template_params: str | Unset = UNSET
    time_grain_sqla: list[list[str]] | Unset = UNSET
    type_: str | Unset = UNSET
    uid: str | Unset = UNSET
    verbose_map: DashboardDatasetSchemaVerboseMap | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        always_filter_main_dttm = self.always_filter_main_dttm

        cache_timeout = self.cache_timeout

        column_formats: dict[str, Any] | Unset = UNSET
        if not isinstance(self.column_formats, Unset):
            column_formats = self.column_formats.to_dict()

        column_names: list[str] | Unset = UNSET
        if not isinstance(self.column_names, Unset):
            column_names = self.column_names

        column_types: list[int] | Unset = UNSET
        if not isinstance(self.column_types, Unset):
            column_types = self.column_types

        columns: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = []
            for columns_item_data in self.columns:
                columns_item = columns_item_data.to_dict()
                columns.append(columns_item)

        database: dict[str, Any] | Unset = UNSET
        if not isinstance(self.database, Unset):
            database = self.database.to_dict()

        datasource_name = self.datasource_name

        default_endpoint = self.default_endpoint

        edit_url = self.edit_url

        fetch_values_predicate = self.fetch_values_predicate

        filter_select = self.filter_select

        filter_select_enabled = self.filter_select_enabled

        granularity_sqla: list[list[str]] | Unset = UNSET
        if not isinstance(self.granularity_sqla, Unset):
            granularity_sqla = []
            for granularity_sqla_item_data in self.granularity_sqla:
                granularity_sqla_item = granularity_sqla_item_data

                granularity_sqla.append(granularity_sqla_item)

        health_check_message = self.health_check_message

        id = self.id

        is_sqllab_view = self.is_sqllab_view

        main_dttm_col = self.main_dttm_col

        metrics: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.metrics, Unset):
            metrics = []
            for metrics_item_data in self.metrics:
                metrics_item = metrics_item_data.to_dict()
                metrics.append(metrics_item)

        name = self.name

        normalize_columns = self.normalize_columns

        offset = self.offset

        order_by_choices: list[list[str]] | Unset = UNSET
        if not isinstance(self.order_by_choices, Unset):
            order_by_choices = []
            for order_by_choices_item_data in self.order_by_choices:
                order_by_choices_item = order_by_choices_item_data

                order_by_choices.append(order_by_choices_item)

        owners: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = []
            for owners_item_data in self.owners:
                owners_item = owners_item_data.to_dict()
                owners.append(owners_item)

        params = self.params

        perm = self.perm

        schema = self.schema

        select_star = self.select_star

        sql = self.sql

        table_name = self.table_name

        template_params = self.template_params

        time_grain_sqla: list[list[str]] | Unset = UNSET
        if not isinstance(self.time_grain_sqla, Unset):
            time_grain_sqla = []
            for time_grain_sqla_item_data in self.time_grain_sqla:
                time_grain_sqla_item = time_grain_sqla_item_data

                time_grain_sqla.append(time_grain_sqla_item)

        type_ = self.type_

        uid = self.uid

        verbose_map: dict[str, Any] | Unset = UNSET
        if not isinstance(self.verbose_map, Unset):
            verbose_map = self.verbose_map.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if always_filter_main_dttm is not UNSET:
            field_dict["always_filter_main_dttm"] = always_filter_main_dttm
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if column_formats is not UNSET:
            field_dict["column_formats"] = column_formats
        if column_names is not UNSET:
            field_dict["column_names"] = column_names
        if column_types is not UNSET:
            field_dict["column_types"] = column_types
        if columns is not UNSET:
            field_dict["columns"] = columns
        if database is not UNSET:
            field_dict["database"] = database
        if datasource_name is not UNSET:
            field_dict["datasource_name"] = datasource_name
        if default_endpoint is not UNSET:
            field_dict["default_endpoint"] = default_endpoint
        if edit_url is not UNSET:
            field_dict["edit_url"] = edit_url
        if fetch_values_predicate is not UNSET:
            field_dict["fetch_values_predicate"] = fetch_values_predicate
        if filter_select is not UNSET:
            field_dict["filter_select"] = filter_select
        if filter_select_enabled is not UNSET:
            field_dict["filter_select_enabled"] = filter_select_enabled
        if granularity_sqla is not UNSET:
            field_dict["granularity_sqla"] = granularity_sqla
        if health_check_message is not UNSET:
            field_dict["health_check_message"] = health_check_message
        if id is not UNSET:
            field_dict["id"] = id
        if is_sqllab_view is not UNSET:
            field_dict["is_sqllab_view"] = is_sqllab_view
        if main_dttm_col is not UNSET:
            field_dict["main_dttm_col"] = main_dttm_col
        if metrics is not UNSET:
            field_dict["metrics"] = metrics
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
        if params is not UNSET:
            field_dict["params"] = params
        if perm is not UNSET:
            field_dict["perm"] = perm
        if schema is not UNSET:
            field_dict["schema"] = schema
        if select_star is not UNSET:
            field_dict["select_star"] = select_star
        if sql is not UNSET:
            field_dict["sql"] = sql
        if table_name is not UNSET:
            field_dict["table_name"] = table_name
        if template_params is not UNSET:
            field_dict["template_params"] = template_params
        if time_grain_sqla is not UNSET:
            field_dict["time_grain_sqla"] = time_grain_sqla
        if type_ is not UNSET:
            field_dict["type"] = type_
        if uid is not UNSET:
            field_dict["uid"] = uid
        if verbose_map is not UNSET:
            field_dict["verbose_map"] = verbose_map

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard_dataset_schema_column_formats import DashboardDatasetSchemaColumnFormats
        from ..models.dashboard_dataset_schema_columns_item import DashboardDatasetSchemaColumnsItem
        from ..models.dashboard_dataset_schema_metrics_item import DashboardDatasetSchemaMetricsItem
        from ..models.dashboard_dataset_schema_owners_item import DashboardDatasetSchemaOwnersItem
        from ..models.dashboard_dataset_schema_verbose_map import DashboardDatasetSchemaVerboseMap
        from ..models.database import Database

        d = dict(src_dict)
        always_filter_main_dttm = d.pop("always_filter_main_dttm", UNSET)

        cache_timeout = d.pop("cache_timeout", UNSET)

        _column_formats = d.pop("column_formats", UNSET)
        column_formats: DashboardDatasetSchemaColumnFormats | Unset
        if isinstance(_column_formats, Unset):
            column_formats = UNSET
        else:
            column_formats = DashboardDatasetSchemaColumnFormats.from_dict(_column_formats)

        column_names = cast(list[str], d.pop("column_names", UNSET))

        column_types = cast(list[int], d.pop("column_types", UNSET))

        _columns = d.pop("columns", UNSET)
        columns: list[DashboardDatasetSchemaColumnsItem] | Unset = UNSET
        if _columns is not UNSET:
            columns = []
            for columns_item_data in _columns:
                columns_item = DashboardDatasetSchemaColumnsItem.from_dict(columns_item_data)

                columns.append(columns_item)

        _database = d.pop("database", UNSET)
        database: Database | Unset
        if isinstance(_database, Unset):
            database = UNSET
        else:
            database = Database.from_dict(_database)

        datasource_name = d.pop("datasource_name", UNSET)

        default_endpoint = d.pop("default_endpoint", UNSET)

        edit_url = d.pop("edit_url", UNSET)

        fetch_values_predicate = d.pop("fetch_values_predicate", UNSET)

        filter_select = d.pop("filter_select", UNSET)

        filter_select_enabled = d.pop("filter_select_enabled", UNSET)

        _granularity_sqla = d.pop("granularity_sqla", UNSET)
        granularity_sqla: list[list[str]] | Unset = UNSET
        if _granularity_sqla is not UNSET:
            granularity_sqla = []
            for granularity_sqla_item_data in _granularity_sqla:
                granularity_sqla_item = cast(list[str], granularity_sqla_item_data)

                granularity_sqla.append(granularity_sqla_item)

        health_check_message = d.pop("health_check_message", UNSET)

        id = d.pop("id", UNSET)

        is_sqllab_view = d.pop("is_sqllab_view", UNSET)

        main_dttm_col = d.pop("main_dttm_col", UNSET)

        _metrics = d.pop("metrics", UNSET)
        metrics: list[DashboardDatasetSchemaMetricsItem] | Unset = UNSET
        if _metrics is not UNSET:
            metrics = []
            for metrics_item_data in _metrics:
                metrics_item = DashboardDatasetSchemaMetricsItem.from_dict(metrics_item_data)

                metrics.append(metrics_item)

        name = d.pop("name", UNSET)

        normalize_columns = d.pop("normalize_columns", UNSET)

        offset = d.pop("offset", UNSET)

        _order_by_choices = d.pop("order_by_choices", UNSET)
        order_by_choices: list[list[str]] | Unset = UNSET
        if _order_by_choices is not UNSET:
            order_by_choices = []
            for order_by_choices_item_data in _order_by_choices:
                order_by_choices_item = cast(list[str], order_by_choices_item_data)

                order_by_choices.append(order_by_choices_item)

        _owners = d.pop("owners", UNSET)
        owners: list[DashboardDatasetSchemaOwnersItem] | Unset = UNSET
        if _owners is not UNSET:
            owners = []
            for owners_item_data in _owners:
                owners_item = DashboardDatasetSchemaOwnersItem.from_dict(owners_item_data)

                owners.append(owners_item)

        params = d.pop("params", UNSET)

        perm = d.pop("perm", UNSET)

        schema = d.pop("schema", UNSET)

        select_star = d.pop("select_star", UNSET)

        sql = d.pop("sql", UNSET)

        table_name = d.pop("table_name", UNSET)

        template_params = d.pop("template_params", UNSET)

        _time_grain_sqla = d.pop("time_grain_sqla", UNSET)
        time_grain_sqla: list[list[str]] | Unset = UNSET
        if _time_grain_sqla is not UNSET:
            time_grain_sqla = []
            for time_grain_sqla_item_data in _time_grain_sqla:
                time_grain_sqla_item = cast(list[str], time_grain_sqla_item_data)

                time_grain_sqla.append(time_grain_sqla_item)

        type_ = d.pop("type", UNSET)

        uid = d.pop("uid", UNSET)

        _verbose_map = d.pop("verbose_map", UNSET)
        verbose_map: DashboardDatasetSchemaVerboseMap | Unset
        if isinstance(_verbose_map, Unset):
            verbose_map = UNSET
        else:
            verbose_map = DashboardDatasetSchemaVerboseMap.from_dict(_verbose_map)

        dashboard_dataset_schema = cls(
            always_filter_main_dttm=always_filter_main_dttm,
            cache_timeout=cache_timeout,
            column_formats=column_formats,
            column_names=column_names,
            column_types=column_types,
            columns=columns,
            database=database,
            datasource_name=datasource_name,
            default_endpoint=default_endpoint,
            edit_url=edit_url,
            fetch_values_predicate=fetch_values_predicate,
            filter_select=filter_select,
            filter_select_enabled=filter_select_enabled,
            granularity_sqla=granularity_sqla,
            health_check_message=health_check_message,
            id=id,
            is_sqllab_view=is_sqllab_view,
            main_dttm_col=main_dttm_col,
            metrics=metrics,
            name=name,
            normalize_columns=normalize_columns,
            offset=offset,
            order_by_choices=order_by_choices,
            owners=owners,
            params=params,
            perm=perm,
            schema=schema,
            select_star=select_star,
            sql=sql,
            table_name=table_name,
            template_params=template_params,
            time_grain_sqla=time_grain_sqla,
            type_=type_,
            uid=uid,
            verbose_map=verbose_map,
        )

        dashboard_dataset_schema.additional_properties = d
        return dashboard_dataset_schema

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

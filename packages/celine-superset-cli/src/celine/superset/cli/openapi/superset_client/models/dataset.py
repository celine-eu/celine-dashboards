from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_column_formats import DatasetColumnFormats
    from ..models.dataset_columns_item import DatasetColumnsItem
    from ..models.dataset_database import DatasetDatabase
    from ..models.dataset_extra import DatasetExtra
    from ..models.dataset_granularity_sqla_item_item import DatasetGranularitySqlaItemItem
    from ..models.dataset_metrics_item import DatasetMetricsItem
    from ..models.dataset_params import DatasetParams
    from ..models.dataset_template_params import DatasetTemplateParams
    from ..models.dataset_verbose_map import DatasetVerboseMap


T = TypeVar("T", bound="Dataset")


@_attrs_define
class Dataset:
    """
    Attributes:
        cache_timeout (int | Unset): Duration (in seconds) of the caching timeout for this dataset.
        column_formats (DatasetColumnFormats | Unset): Column formats.
        columns (list[DatasetColumnsItem] | Unset): Columns metadata.
        database (DatasetDatabase | Unset): Database associated with the dataset.
        datasource_name (str | Unset): Dataset name.
        default_endpoint (str | Unset): Default endpoint for the dataset.
        description (str | Unset): Dataset description.
        edit_url (str | Unset): The URL for editing the dataset.
        extra (DatasetExtra | Unset): JSON string containing extra configuration elements.
        fetch_values_predicate (str | Unset): Predicate used when fetching values from the dataset.
        filter_select (bool | Unset): SELECT filter applied to the dataset.
        filter_select_enabled (bool | Unset): If the SELECT filter is enabled.
        granularity_sqla (list[list[DatasetGranularitySqlaItemItem]] | Unset): Name of temporal column used for time
            filtering for SQL datasources. This field is deprecated, use `granularity` instead.
        health_check_message (str | Unset): Health check message.
        id (int | Unset): Dataset ID.
        is_sqllab_view (bool | Unset): If the dataset is a SQL Lab view.
        main_dttm_col (str | Unset): The main temporal column.
        metrics (list[DatasetMetricsItem] | Unset): Dataset metrics.
        name (str | Unset): Dataset name.
        offset (int | Unset): Dataset offset.
        order_by_choices (list[list[str]] | Unset): List of order by columns.
        owners (list[int] | Unset): List of owners identifiers
        params (DatasetParams | Unset): Extra params for the dataset.
        perm (str | Unset): Permission expression.
        schema (str | Unset): Dataset schema.
        select_star (str | Unset): Select all clause.
        sql (str | Unset): A SQL statement that defines the dataset.
        table_name (str | Unset): The name of the table associated with the dataset.
        template_params (DatasetTemplateParams | Unset): Table template params.
        time_grain_sqla (list[list[str]] | Unset): List of temporal granularities supported by the dataset.
        type_ (str | Unset): Dataset type.
        uid (str | Unset): Dataset unique identifier.
        verbose_map (DatasetVerboseMap | Unset): Mapping from raw name to verbose name.
    """

    cache_timeout: int | Unset = UNSET
    column_formats: DatasetColumnFormats | Unset = UNSET
    columns: list[DatasetColumnsItem] | Unset = UNSET
    database: DatasetDatabase | Unset = UNSET
    datasource_name: str | Unset = UNSET
    default_endpoint: str | Unset = UNSET
    description: str | Unset = UNSET
    edit_url: str | Unset = UNSET
    extra: DatasetExtra | Unset = UNSET
    fetch_values_predicate: str | Unset = UNSET
    filter_select: bool | Unset = UNSET
    filter_select_enabled: bool | Unset = UNSET
    granularity_sqla: list[list[DatasetGranularitySqlaItemItem]] | Unset = UNSET
    health_check_message: str | Unset = UNSET
    id: int | Unset = UNSET
    is_sqllab_view: bool | Unset = UNSET
    main_dttm_col: str | Unset = UNSET
    metrics: list[DatasetMetricsItem] | Unset = UNSET
    name: str | Unset = UNSET
    offset: int | Unset = UNSET
    order_by_choices: list[list[str]] | Unset = UNSET
    owners: list[int] | Unset = UNSET
    params: DatasetParams | Unset = UNSET
    perm: str | Unset = UNSET
    schema: str | Unset = UNSET
    select_star: str | Unset = UNSET
    sql: str | Unset = UNSET
    table_name: str | Unset = UNSET
    template_params: DatasetTemplateParams | Unset = UNSET
    time_grain_sqla: list[list[str]] | Unset = UNSET
    type_: str | Unset = UNSET
    uid: str | Unset = UNSET
    verbose_map: DatasetVerboseMap | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cache_timeout = self.cache_timeout

        column_formats: dict[str, Any] | Unset = UNSET
        if not isinstance(self.column_formats, Unset):
            column_formats = self.column_formats.to_dict()

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

        description = self.description

        edit_url = self.edit_url

        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        fetch_values_predicate = self.fetch_values_predicate

        filter_select = self.filter_select

        filter_select_enabled = self.filter_select_enabled

        granularity_sqla: list[list[dict[str, Any]]] | Unset = UNSET
        if not isinstance(self.granularity_sqla, Unset):
            granularity_sqla = []
            for granularity_sqla_item_data in self.granularity_sqla:
                granularity_sqla_item = []
                for granularity_sqla_item_item_data in granularity_sqla_item_data:
                    granularity_sqla_item_item = granularity_sqla_item_item_data.to_dict()
                    granularity_sqla_item.append(granularity_sqla_item_item)

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

        offset = self.offset

        order_by_choices: list[list[str]] | Unset = UNSET
        if not isinstance(self.order_by_choices, Unset):
            order_by_choices = []
            for order_by_choices_item_data in self.order_by_choices:
                order_by_choices_item = order_by_choices_item_data

                order_by_choices.append(order_by_choices_item)

        owners: list[int] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners

        params: dict[str, Any] | Unset = UNSET
        if not isinstance(self.params, Unset):
            params = self.params.to_dict()

        perm = self.perm

        schema = self.schema

        select_star = self.select_star

        sql = self.sql

        table_name = self.table_name

        template_params: dict[str, Any] | Unset = UNSET
        if not isinstance(self.template_params, Unset):
            template_params = self.template_params.to_dict()

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
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if column_formats is not UNSET:
            field_dict["column_formats"] = column_formats
        if columns is not UNSET:
            field_dict["columns"] = columns
        if database is not UNSET:
            field_dict["database"] = database
        if datasource_name is not UNSET:
            field_dict["datasource_name"] = datasource_name
        if default_endpoint is not UNSET:
            field_dict["default_endpoint"] = default_endpoint
        if description is not UNSET:
            field_dict["description"] = description
        if edit_url is not UNSET:
            field_dict["edit_url"] = edit_url
        if extra is not UNSET:
            field_dict["extra"] = extra
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
        from ..models.dataset_column_formats import DatasetColumnFormats
        from ..models.dataset_columns_item import DatasetColumnsItem
        from ..models.dataset_database import DatasetDatabase
        from ..models.dataset_extra import DatasetExtra
        from ..models.dataset_granularity_sqla_item_item import DatasetGranularitySqlaItemItem
        from ..models.dataset_metrics_item import DatasetMetricsItem
        from ..models.dataset_params import DatasetParams
        from ..models.dataset_template_params import DatasetTemplateParams
        from ..models.dataset_verbose_map import DatasetVerboseMap

        d = dict(src_dict)
        cache_timeout = d.pop("cache_timeout", UNSET)

        _column_formats = d.pop("column_formats", UNSET)
        column_formats: DatasetColumnFormats | Unset
        if isinstance(_column_formats, Unset):
            column_formats = UNSET
        else:
            column_formats = DatasetColumnFormats.from_dict(_column_formats)

        _columns = d.pop("columns", UNSET)
        columns: list[DatasetColumnsItem] | Unset = UNSET
        if _columns is not UNSET:
            columns = []
            for columns_item_data in _columns:
                columns_item = DatasetColumnsItem.from_dict(columns_item_data)

                columns.append(columns_item)

        _database = d.pop("database", UNSET)
        database: DatasetDatabase | Unset
        if isinstance(_database, Unset):
            database = UNSET
        else:
            database = DatasetDatabase.from_dict(_database)

        datasource_name = d.pop("datasource_name", UNSET)

        default_endpoint = d.pop("default_endpoint", UNSET)

        description = d.pop("description", UNSET)

        edit_url = d.pop("edit_url", UNSET)

        _extra = d.pop("extra", UNSET)
        extra: DatasetExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = DatasetExtra.from_dict(_extra)

        fetch_values_predicate = d.pop("fetch_values_predicate", UNSET)

        filter_select = d.pop("filter_select", UNSET)

        filter_select_enabled = d.pop("filter_select_enabled", UNSET)

        _granularity_sqla = d.pop("granularity_sqla", UNSET)
        granularity_sqla: list[list[DatasetGranularitySqlaItemItem]] | Unset = UNSET
        if _granularity_sqla is not UNSET:
            granularity_sqla = []
            for granularity_sqla_item_data in _granularity_sqla:
                granularity_sqla_item = []
                _granularity_sqla_item = granularity_sqla_item_data
                for granularity_sqla_item_item_data in _granularity_sqla_item:
                    granularity_sqla_item_item = DatasetGranularitySqlaItemItem.from_dict(
                        granularity_sqla_item_item_data
                    )

                    granularity_sqla_item.append(granularity_sqla_item_item)

                granularity_sqla.append(granularity_sqla_item)

        health_check_message = d.pop("health_check_message", UNSET)

        id = d.pop("id", UNSET)

        is_sqllab_view = d.pop("is_sqllab_view", UNSET)

        main_dttm_col = d.pop("main_dttm_col", UNSET)

        _metrics = d.pop("metrics", UNSET)
        metrics: list[DatasetMetricsItem] | Unset = UNSET
        if _metrics is not UNSET:
            metrics = []
            for metrics_item_data in _metrics:
                metrics_item = DatasetMetricsItem.from_dict(metrics_item_data)

                metrics.append(metrics_item)

        name = d.pop("name", UNSET)

        offset = d.pop("offset", UNSET)

        _order_by_choices = d.pop("order_by_choices", UNSET)
        order_by_choices: list[list[str]] | Unset = UNSET
        if _order_by_choices is not UNSET:
            order_by_choices = []
            for order_by_choices_item_data in _order_by_choices:
                order_by_choices_item = cast(list[str], order_by_choices_item_data)

                order_by_choices.append(order_by_choices_item)

        owners = cast(list[int], d.pop("owners", UNSET))

        _params = d.pop("params", UNSET)
        params: DatasetParams | Unset
        if isinstance(_params, Unset):
            params = UNSET
        else:
            params = DatasetParams.from_dict(_params)

        perm = d.pop("perm", UNSET)

        schema = d.pop("schema", UNSET)

        select_star = d.pop("select_star", UNSET)

        sql = d.pop("sql", UNSET)

        table_name = d.pop("table_name", UNSET)

        _template_params = d.pop("template_params", UNSET)
        template_params: DatasetTemplateParams | Unset
        if isinstance(_template_params, Unset):
            template_params = UNSET
        else:
            template_params = DatasetTemplateParams.from_dict(_template_params)

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
        verbose_map: DatasetVerboseMap | Unset
        if isinstance(_verbose_map, Unset):
            verbose_map = UNSET
        else:
            verbose_map = DatasetVerboseMap.from_dict(_verbose_map)

        dataset = cls(
            cache_timeout=cache_timeout,
            column_formats=column_formats,
            columns=columns,
            database=database,
            datasource_name=datasource_name,
            default_endpoint=default_endpoint,
            description=description,
            edit_url=edit_url,
            extra=extra,
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

        dataset.additional_properties = d
        return dataset

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

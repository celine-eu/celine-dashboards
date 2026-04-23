from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_query_object_result_type_type_1 import (
    ChartDataQueryObjectResultTypeType1,
    check_chart_data_query_object_result_type_type_1,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.annotation_layer import AnnotationLayer
    from ..models.chart_data_datasource import ChartDataDatasource
    from ..models.chart_data_extras import ChartDataExtras
    from ..models.chart_data_filter import ChartDataFilter
    from ..models.chart_data_post_processing_operation import ChartDataPostProcessingOperation
    from ..models.chart_data_query_object_applied_time_extras_type_0 import ChartDataQueryObjectAppliedTimeExtrasType0
    from ..models.chart_data_query_object_url_params_type_0 import ChartDataQueryObjectUrlParamsType0


T = TypeVar("T", bound="ChartDataQueryObject")


@_attrs_define
class ChartDataQueryObject:
    """
    Attributes:
        annotation_layers (list[AnnotationLayer] | None | Unset): Annotation layers to apply to chart
        applied_time_extras (ChartDataQueryObjectAppliedTimeExtrasType0 | None | Unset): A mapping of temporal extras
            that have been applied to the query Example: {'__time_range': '1 year ago : now'}.
        apply_fetch_values_predicate (bool | None | Unset): Add fetch values predicate (where clause) to query if
            defined in datasource
        columns (list[Any] | None | Unset): Columns which to select in the query.
        datasource (ChartDataDatasource | None | Unset):
        extras (ChartDataExtras | None | Unset): Extra parameters to add to the query.
        filters (list[ChartDataFilter] | None | Unset):
        granularity (None | str | Unset): Name of temporal column used for time filtering.
        granularity_sqla (None | str | Unset): Name of temporal column used for time filtering for SQL datasources. This
            field is deprecated, use `granularity` instead.
        group_others_when_limit_reached (bool | None | Unset): When true, groups remaining series into an 'Others'
            category when series limit is reached. Prevents incomplete data. Default: False.
        groupby (list[Any] | None | Unset): Columns by which to group the query. This field is deprecated, use `columns`
            instead.
        having (None | str | Unset): HAVING clause to be added to aggregate queries using AND operator. This field is
            deprecated and should be passed to `extras`.
        is_rowcount (bool | None | Unset): Should the rowcount of the actual query be returned
        is_timeseries (bool | None | Unset): Is the `query_object` a timeseries.
        metrics (list[Any] | None | Unset): Aggregate expressions. Metrics can be passed as both references to
            datasource metrics (strings), or ad-hoc metricswhich are defined only within the query object. See
            `ChartDataAdhocMetricSchema` for the structure of ad-hoc metrics.
        order_desc (bool | None | Unset): Reverse order. Default: `false`
        orderby (list[Any] | None | Unset): Expects a list of lists where the first element is the column name which to
            sort by, and the second element is a boolean. Example: [['my_col_1', False], ['my_col_2', True]].
        post_processing (list[ChartDataPostProcessingOperation | None] | None | Unset): Post processing operations to be
            applied to the result set. Operations are applied to the result set in sequential order.
        result_type (ChartDataQueryObjectResultTypeType1 | None | Unset):
        row_limit (int | None | Unset): Maximum row count (0=disabled). Default: `config["ROW_LIMIT"]`
        row_offset (int | None | Unset): Number of rows to skip. Default: `0`
        series_columns (list[Any] | None | Unset): Columns to use when limiting series count. All columns must be
            present in the `columns` property. Requires `series_limit` and `series_limit_metric` to be set.
        series_limit (int | None | Unset): Maximum number of series. Requires `series` and `series_limit_metric` to be
            set.
        series_limit_metric (Any | Unset): Metric used to limit timeseries queries by. Requires `series` and
            `series_limit` to be set.
        time_offsets (list[str] | None | Unset):
        time_range (None | str | Unset): A time rage, either expressed as a colon separated string `since : until` or
            human readable freeform. Valid formats for `since` and `until` are:
            - ISO 8601
            - X days/years/hours/day/year/weeks
            - X days/years/hours/day/year/weeks ago
            - X days/years/hours/day/year/weeks from now

            Additionally, the following freeform can be used:

            - Last day
            - Last week
            - Last month
            - Last quarter
            - Last year
            - No filter
            - Last X seconds/minutes/hours/days/weeks/months/years
            - Next X seconds/minutes/hours/days/weeks/months/years
             Example: Last week.
        time_shift (None | str | Unset): A human-readable date/time string. Please refer to
            [parsdatetime](https://github.com/bear/parsedatetime) documentation for details on valid values.
        timeseries_limit (int | None | Unset): Maximum row count for timeseries queries. This field is deprecated, use
            `series_limit` instead.Default: `0`
        timeseries_limit_metric (Any | Unset): Metric used to limit timeseries queries by. This field is deprecated, use
            `series_limit_metric` instead.
        url_params (ChartDataQueryObjectUrlParamsType0 | None | Unset): Optional query parameters passed to a dashboard
            or Explore  view
        where (None | str | Unset): WHERE clause to be added to queries using AND operator.This field is deprecated and
            should be passed to `extras`.
    """

    annotation_layers: list[AnnotationLayer] | None | Unset = UNSET
    applied_time_extras: ChartDataQueryObjectAppliedTimeExtrasType0 | None | Unset = UNSET
    apply_fetch_values_predicate: bool | None | Unset = UNSET
    columns: list[Any] | None | Unset = UNSET
    datasource: ChartDataDatasource | None | Unset = UNSET
    extras: ChartDataExtras | None | Unset = UNSET
    filters: list[ChartDataFilter] | None | Unset = UNSET
    granularity: None | str | Unset = UNSET
    granularity_sqla: None | str | Unset = UNSET
    group_others_when_limit_reached: bool | None | Unset = False
    groupby: list[Any] | None | Unset = UNSET
    having: None | str | Unset = UNSET
    is_rowcount: bool | None | Unset = UNSET
    is_timeseries: bool | None | Unset = UNSET
    metrics: list[Any] | None | Unset = UNSET
    order_desc: bool | None | Unset = UNSET
    orderby: list[Any] | None | Unset = UNSET
    post_processing: list[ChartDataPostProcessingOperation | None] | None | Unset = UNSET
    result_type: ChartDataQueryObjectResultTypeType1 | None | Unset = UNSET
    row_limit: int | None | Unset = UNSET
    row_offset: int | None | Unset = UNSET
    series_columns: list[Any] | None | Unset = UNSET
    series_limit: int | None | Unset = UNSET
    series_limit_metric: Any | Unset = UNSET
    time_offsets: list[str] | None | Unset = UNSET
    time_range: None | str | Unset = UNSET
    time_shift: None | str | Unset = UNSET
    timeseries_limit: int | None | Unset = UNSET
    timeseries_limit_metric: Any | Unset = UNSET
    url_params: ChartDataQueryObjectUrlParamsType0 | None | Unset = UNSET
    where: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.chart_data_datasource import ChartDataDatasource
        from ..models.chart_data_extras import ChartDataExtras
        from ..models.chart_data_post_processing_operation import ChartDataPostProcessingOperation
        from ..models.chart_data_query_object_applied_time_extras_type_0 import (
            ChartDataQueryObjectAppliedTimeExtrasType0,
        )
        from ..models.chart_data_query_object_url_params_type_0 import ChartDataQueryObjectUrlParamsType0

        annotation_layers: list[dict[str, Any]] | None | Unset
        if isinstance(self.annotation_layers, Unset):
            annotation_layers = UNSET
        elif isinstance(self.annotation_layers, list):
            annotation_layers = []
            for annotation_layers_type_0_item_data in self.annotation_layers:
                annotation_layers_type_0_item = annotation_layers_type_0_item_data.to_dict()
                annotation_layers.append(annotation_layers_type_0_item)

        else:
            annotation_layers = self.annotation_layers

        applied_time_extras: dict[str, Any] | None | Unset
        if isinstance(self.applied_time_extras, Unset):
            applied_time_extras = UNSET
        elif isinstance(self.applied_time_extras, ChartDataQueryObjectAppliedTimeExtrasType0):
            applied_time_extras = self.applied_time_extras.to_dict()
        else:
            applied_time_extras = self.applied_time_extras

        apply_fetch_values_predicate: bool | None | Unset
        if isinstance(self.apply_fetch_values_predicate, Unset):
            apply_fetch_values_predicate = UNSET
        else:
            apply_fetch_values_predicate = self.apply_fetch_values_predicate

        columns: list[Any] | None | Unset
        if isinstance(self.columns, Unset):
            columns = UNSET
        elif isinstance(self.columns, list):
            columns = self.columns

        else:
            columns = self.columns

        datasource: dict[str, Any] | None | Unset
        if isinstance(self.datasource, Unset):
            datasource = UNSET
        elif isinstance(self.datasource, ChartDataDatasource):
            datasource = self.datasource.to_dict()
        else:
            datasource = self.datasource

        extras: dict[str, Any] | None | Unset
        if isinstance(self.extras, Unset):
            extras = UNSET
        elif isinstance(self.extras, ChartDataExtras):
            extras = self.extras.to_dict()
        else:
            extras = self.extras

        filters: list[dict[str, Any]] | None | Unset
        if isinstance(self.filters, Unset):
            filters = UNSET
        elif isinstance(self.filters, list):
            filters = []
            for filters_type_0_item_data in self.filters:
                filters_type_0_item = filters_type_0_item_data.to_dict()
                filters.append(filters_type_0_item)

        else:
            filters = self.filters

        granularity: None | str | Unset
        if isinstance(self.granularity, Unset):
            granularity = UNSET
        else:
            granularity = self.granularity

        granularity_sqla: None | str | Unset
        if isinstance(self.granularity_sqla, Unset):
            granularity_sqla = UNSET
        else:
            granularity_sqla = self.granularity_sqla

        group_others_when_limit_reached: bool | None | Unset
        if isinstance(self.group_others_when_limit_reached, Unset):
            group_others_when_limit_reached = UNSET
        else:
            group_others_when_limit_reached = self.group_others_when_limit_reached

        groupby: list[Any] | None | Unset
        if isinstance(self.groupby, Unset):
            groupby = UNSET
        elif isinstance(self.groupby, list):
            groupby = self.groupby

        else:
            groupby = self.groupby

        having: None | str | Unset
        if isinstance(self.having, Unset):
            having = UNSET
        else:
            having = self.having

        is_rowcount: bool | None | Unset
        if isinstance(self.is_rowcount, Unset):
            is_rowcount = UNSET
        else:
            is_rowcount = self.is_rowcount

        is_timeseries: bool | None | Unset
        if isinstance(self.is_timeseries, Unset):
            is_timeseries = UNSET
        else:
            is_timeseries = self.is_timeseries

        metrics: list[Any] | None | Unset
        if isinstance(self.metrics, Unset):
            metrics = UNSET
        elif isinstance(self.metrics, list):
            metrics = self.metrics

        else:
            metrics = self.metrics

        order_desc: bool | None | Unset
        if isinstance(self.order_desc, Unset):
            order_desc = UNSET
        else:
            order_desc = self.order_desc

        orderby: list[Any] | None | Unset
        if isinstance(self.orderby, Unset):
            orderby = UNSET
        elif isinstance(self.orderby, list):
            orderby = self.orderby

        else:
            orderby = self.orderby

        post_processing: list[dict[str, Any] | None] | None | Unset
        if isinstance(self.post_processing, Unset):
            post_processing = UNSET
        elif isinstance(self.post_processing, list):
            post_processing = []
            for post_processing_type_0_item_data in self.post_processing:
                post_processing_type_0_item: dict[str, Any] | None
                if isinstance(post_processing_type_0_item_data, ChartDataPostProcessingOperation):
                    post_processing_type_0_item = post_processing_type_0_item_data.to_dict()
                else:
                    post_processing_type_0_item = post_processing_type_0_item_data
                post_processing.append(post_processing_type_0_item)

        else:
            post_processing = self.post_processing

        result_type: None | str | Unset
        if isinstance(self.result_type, Unset):
            result_type = UNSET
        elif isinstance(self.result_type, str):
            result_type = self.result_type
        else:
            result_type = self.result_type

        row_limit: int | None | Unset
        if isinstance(self.row_limit, Unset):
            row_limit = UNSET
        else:
            row_limit = self.row_limit

        row_offset: int | None | Unset
        if isinstance(self.row_offset, Unset):
            row_offset = UNSET
        else:
            row_offset = self.row_offset

        series_columns: list[Any] | None | Unset
        if isinstance(self.series_columns, Unset):
            series_columns = UNSET
        elif isinstance(self.series_columns, list):
            series_columns = self.series_columns

        else:
            series_columns = self.series_columns

        series_limit: int | None | Unset
        if isinstance(self.series_limit, Unset):
            series_limit = UNSET
        else:
            series_limit = self.series_limit

        series_limit_metric = self.series_limit_metric

        time_offsets: list[str] | None | Unset
        if isinstance(self.time_offsets, Unset):
            time_offsets = UNSET
        elif isinstance(self.time_offsets, list):
            time_offsets = self.time_offsets

        else:
            time_offsets = self.time_offsets

        time_range: None | str | Unset
        if isinstance(self.time_range, Unset):
            time_range = UNSET
        else:
            time_range = self.time_range

        time_shift: None | str | Unset
        if isinstance(self.time_shift, Unset):
            time_shift = UNSET
        else:
            time_shift = self.time_shift

        timeseries_limit: int | None | Unset
        if isinstance(self.timeseries_limit, Unset):
            timeseries_limit = UNSET
        else:
            timeseries_limit = self.timeseries_limit

        timeseries_limit_metric = self.timeseries_limit_metric

        url_params: dict[str, Any] | None | Unset
        if isinstance(self.url_params, Unset):
            url_params = UNSET
        elif isinstance(self.url_params, ChartDataQueryObjectUrlParamsType0):
            url_params = self.url_params.to_dict()
        else:
            url_params = self.url_params

        where: None | str | Unset
        if isinstance(self.where, Unset):
            where = UNSET
        else:
            where = self.where

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if annotation_layers is not UNSET:
            field_dict["annotation_layers"] = annotation_layers
        if applied_time_extras is not UNSET:
            field_dict["applied_time_extras"] = applied_time_extras
        if apply_fetch_values_predicate is not UNSET:
            field_dict["apply_fetch_values_predicate"] = apply_fetch_values_predicate
        if columns is not UNSET:
            field_dict["columns"] = columns
        if datasource is not UNSET:
            field_dict["datasource"] = datasource
        if extras is not UNSET:
            field_dict["extras"] = extras
        if filters is not UNSET:
            field_dict["filters"] = filters
        if granularity is not UNSET:
            field_dict["granularity"] = granularity
        if granularity_sqla is not UNSET:
            field_dict["granularity_sqla"] = granularity_sqla
        if group_others_when_limit_reached is not UNSET:
            field_dict["group_others_when_limit_reached"] = group_others_when_limit_reached
        if groupby is not UNSET:
            field_dict["groupby"] = groupby
        if having is not UNSET:
            field_dict["having"] = having
        if is_rowcount is not UNSET:
            field_dict["is_rowcount"] = is_rowcount
        if is_timeseries is not UNSET:
            field_dict["is_timeseries"] = is_timeseries
        if metrics is not UNSET:
            field_dict["metrics"] = metrics
        if order_desc is not UNSET:
            field_dict["order_desc"] = order_desc
        if orderby is not UNSET:
            field_dict["orderby"] = orderby
        if post_processing is not UNSET:
            field_dict["post_processing"] = post_processing
        if result_type is not UNSET:
            field_dict["result_type"] = result_type
        if row_limit is not UNSET:
            field_dict["row_limit"] = row_limit
        if row_offset is not UNSET:
            field_dict["row_offset"] = row_offset
        if series_columns is not UNSET:
            field_dict["series_columns"] = series_columns
        if series_limit is not UNSET:
            field_dict["series_limit"] = series_limit
        if series_limit_metric is not UNSET:
            field_dict["series_limit_metric"] = series_limit_metric
        if time_offsets is not UNSET:
            field_dict["time_offsets"] = time_offsets
        if time_range is not UNSET:
            field_dict["time_range"] = time_range
        if time_shift is not UNSET:
            field_dict["time_shift"] = time_shift
        if timeseries_limit is not UNSET:
            field_dict["timeseries_limit"] = timeseries_limit
        if timeseries_limit_metric is not UNSET:
            field_dict["timeseries_limit_metric"] = timeseries_limit_metric
        if url_params is not UNSET:
            field_dict["url_params"] = url_params
        if where is not UNSET:
            field_dict["where"] = where

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.annotation_layer import AnnotationLayer
        from ..models.chart_data_datasource import ChartDataDatasource
        from ..models.chart_data_extras import ChartDataExtras
        from ..models.chart_data_filter import ChartDataFilter
        from ..models.chart_data_post_processing_operation import ChartDataPostProcessingOperation
        from ..models.chart_data_query_object_applied_time_extras_type_0 import (
            ChartDataQueryObjectAppliedTimeExtrasType0,
        )
        from ..models.chart_data_query_object_url_params_type_0 import ChartDataQueryObjectUrlParamsType0

        d = dict(src_dict)

        def _parse_annotation_layers(data: object) -> list[AnnotationLayer] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                annotation_layers_type_0 = []
                _annotation_layers_type_0 = data
                for annotation_layers_type_0_item_data in _annotation_layers_type_0:
                    annotation_layers_type_0_item = AnnotationLayer.from_dict(annotation_layers_type_0_item_data)

                    annotation_layers_type_0.append(annotation_layers_type_0_item)

                return annotation_layers_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AnnotationLayer] | None | Unset, data)

        annotation_layers = _parse_annotation_layers(d.pop("annotation_layers", UNSET))

        def _parse_applied_time_extras(data: object) -> ChartDataQueryObjectAppliedTimeExtrasType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                applied_time_extras_type_0 = ChartDataQueryObjectAppliedTimeExtrasType0.from_dict(data)

                return applied_time_extras_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ChartDataQueryObjectAppliedTimeExtrasType0 | None | Unset, data)

        applied_time_extras = _parse_applied_time_extras(d.pop("applied_time_extras", UNSET))

        def _parse_apply_fetch_values_predicate(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        apply_fetch_values_predicate = _parse_apply_fetch_values_predicate(d.pop("apply_fetch_values_predicate", UNSET))

        def _parse_columns(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                columns_type_0 = cast(list[Any], data)

                return columns_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        columns = _parse_columns(d.pop("columns", UNSET))

        def _parse_datasource(data: object) -> ChartDataDatasource | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                datasource_type_1 = ChartDataDatasource.from_dict(data)

                return datasource_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ChartDataDatasource | None | Unset, data)

        datasource = _parse_datasource(d.pop("datasource", UNSET))

        def _parse_extras(data: object) -> ChartDataExtras | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                extras_type_1 = ChartDataExtras.from_dict(data)

                return extras_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ChartDataExtras | None | Unset, data)

        extras = _parse_extras(d.pop("extras", UNSET))

        def _parse_filters(data: object) -> list[ChartDataFilter] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                filters_type_0 = []
                _filters_type_0 = data
                for filters_type_0_item_data in _filters_type_0:
                    filters_type_0_item = ChartDataFilter.from_dict(filters_type_0_item_data)

                    filters_type_0.append(filters_type_0_item)

                return filters_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[ChartDataFilter] | None | Unset, data)

        filters = _parse_filters(d.pop("filters", UNSET))

        def _parse_granularity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        granularity = _parse_granularity(d.pop("granularity", UNSET))

        def _parse_granularity_sqla(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        granularity_sqla = _parse_granularity_sqla(d.pop("granularity_sqla", UNSET))

        def _parse_group_others_when_limit_reached(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        group_others_when_limit_reached = _parse_group_others_when_limit_reached(
            d.pop("group_others_when_limit_reached", UNSET)
        )

        def _parse_groupby(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                groupby_type_0 = cast(list[Any], data)

                return groupby_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        groupby = _parse_groupby(d.pop("groupby", UNSET))

        def _parse_having(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        having = _parse_having(d.pop("having", UNSET))

        def _parse_is_rowcount(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_rowcount = _parse_is_rowcount(d.pop("is_rowcount", UNSET))

        def _parse_is_timeseries(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_timeseries = _parse_is_timeseries(d.pop("is_timeseries", UNSET))

        def _parse_metrics(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                metrics_type_0 = cast(list[Any], data)

                return metrics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        metrics = _parse_metrics(d.pop("metrics", UNSET))

        def _parse_order_desc(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        order_desc = _parse_order_desc(d.pop("order_desc", UNSET))

        def _parse_orderby(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                orderby_type_0 = cast(list[Any], data)

                return orderby_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        orderby = _parse_orderby(d.pop("orderby", UNSET))

        def _parse_post_processing(data: object) -> list[ChartDataPostProcessingOperation | None] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                post_processing_type_0 = []
                _post_processing_type_0 = data
                for post_processing_type_0_item_data in _post_processing_type_0:

                    def _parse_post_processing_type_0_item(data: object) -> ChartDataPostProcessingOperation | None:
                        if data is None:
                            return data
                        try:
                            if not isinstance(data, dict):
                                raise TypeError()
                            post_processing_type_0_item_type_1 = ChartDataPostProcessingOperation.from_dict(data)

                            return post_processing_type_0_item_type_1
                        except (TypeError, ValueError, AttributeError, KeyError):
                            pass
                        return cast(ChartDataPostProcessingOperation | None, data)

                    post_processing_type_0_item = _parse_post_processing_type_0_item(post_processing_type_0_item_data)

                    post_processing_type_0.append(post_processing_type_0_item)

                return post_processing_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[ChartDataPostProcessingOperation | None] | None | Unset, data)

        post_processing = _parse_post_processing(d.pop("post_processing", UNSET))

        def _parse_result_type(data: object) -> ChartDataQueryObjectResultTypeType1 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                result_type_type_1 = check_chart_data_query_object_result_type_type_1(data)

                return result_type_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ChartDataQueryObjectResultTypeType1 | None | Unset, data)

        result_type = _parse_result_type(d.pop("result_type", UNSET))

        def _parse_row_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        row_limit = _parse_row_limit(d.pop("row_limit", UNSET))

        def _parse_row_offset(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        row_offset = _parse_row_offset(d.pop("row_offset", UNSET))

        def _parse_series_columns(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                series_columns_type_0 = cast(list[Any], data)

                return series_columns_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        series_columns = _parse_series_columns(d.pop("series_columns", UNSET))

        def _parse_series_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        series_limit = _parse_series_limit(d.pop("series_limit", UNSET))

        series_limit_metric = d.pop("series_limit_metric", UNSET)

        def _parse_time_offsets(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                time_offsets_type_0 = cast(list[str], data)

                return time_offsets_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        time_offsets = _parse_time_offsets(d.pop("time_offsets", UNSET))

        def _parse_time_range(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        time_range = _parse_time_range(d.pop("time_range", UNSET))

        def _parse_time_shift(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        time_shift = _parse_time_shift(d.pop("time_shift", UNSET))

        def _parse_timeseries_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        timeseries_limit = _parse_timeseries_limit(d.pop("timeseries_limit", UNSET))

        timeseries_limit_metric = d.pop("timeseries_limit_metric", UNSET)

        def _parse_url_params(data: object) -> ChartDataQueryObjectUrlParamsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                url_params_type_0 = ChartDataQueryObjectUrlParamsType0.from_dict(data)

                return url_params_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ChartDataQueryObjectUrlParamsType0 | None | Unset, data)

        url_params = _parse_url_params(d.pop("url_params", UNSET))

        def _parse_where(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        where = _parse_where(d.pop("where", UNSET))

        chart_data_query_object = cls(
            annotation_layers=annotation_layers,
            applied_time_extras=applied_time_extras,
            apply_fetch_values_predicate=apply_fetch_values_predicate,
            columns=columns,
            datasource=datasource,
            extras=extras,
            filters=filters,
            granularity=granularity,
            granularity_sqla=granularity_sqla,
            group_others_when_limit_reached=group_others_when_limit_reached,
            groupby=groupby,
            having=having,
            is_rowcount=is_rowcount,
            is_timeseries=is_timeseries,
            metrics=metrics,
            order_desc=order_desc,
            orderby=orderby,
            post_processing=post_processing,
            result_type=result_type,
            row_limit=row_limit,
            row_offset=row_offset,
            series_columns=series_columns,
            series_limit=series_limit,
            series_limit_metric=series_limit_metric,
            time_offsets=time_offsets,
            time_range=time_range,
            time_shift=time_shift,
            timeseries_limit=timeseries_limit,
            timeseries_limit_metric=timeseries_limit_metric,
            url_params=url_params,
            where=where,
        )

        chart_data_query_object.additional_properties = d
        return chart_data_query_object

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

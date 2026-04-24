from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_response_result_status import (
    ChartDataResponseResultStatus,
    check_chart_data_response_result_status,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_response_result_annotation_data_type_0_item import (
        ChartDataResponseResultAnnotationDataType0Item,
    )
    from ..models.chart_data_response_result_applied_filters_item import ChartDataResponseResultAppliedFiltersItem
    from ..models.chart_data_response_result_data_item import ChartDataResponseResultDataItem
    from ..models.chart_data_response_result_rejected_filters_item import ChartDataResponseResultRejectedFiltersItem


T = TypeVar("T", bound="ChartDataResponseResult")


@_attrs_define
class ChartDataResponseResult:
    """
    Attributes:
        cache_key (None | str): Unique cache key for query object
        cache_timeout (int | None): Cache timeout in following order: custom timeout, datasource timeout, cache default
            timeout, config default cache timeout.
        cached_dttm (None | str): Cache timestamp
        is_cached (bool): Is the result cached
        annotation_data (list[ChartDataResponseResultAnnotationDataType0Item] | None | Unset): All requested annotation
            data
        applied_filters (list[ChartDataResponseResultAppliedFiltersItem] | Unset): A list with applied filters
        colnames (list[str] | Unset): A list of column names
        coltypes (list[int] | Unset): A list of generic data types of each column
        data (list[ChartDataResponseResultDataItem] | Unset): A list with results
        error (None | str | Unset): Error
        from_dttm (int | None | Unset): Start timestamp of time range
        query (None | str | Unset): The executed query statement. May be absent when validation errors occur.
        rejected_filters (list[ChartDataResponseResultRejectedFiltersItem] | Unset): A list with rejected filters
        rowcount (int | Unset): Amount of rows in result set
        stacktrace (None | str | Unset): Stacktrace if there was an error
        status (ChartDataResponseResultStatus | Unset): Status of the query
        to_dttm (int | None | Unset): End timestamp of time range
    """

    cache_key: None | str
    cache_timeout: int | None
    cached_dttm: None | str
    is_cached: bool
    annotation_data: list[ChartDataResponseResultAnnotationDataType0Item] | None | Unset = UNSET
    applied_filters: list[ChartDataResponseResultAppliedFiltersItem] | Unset = UNSET
    colnames: list[str] | Unset = UNSET
    coltypes: list[int] | Unset = UNSET
    data: list[ChartDataResponseResultDataItem] | Unset = UNSET
    error: None | str | Unset = UNSET
    from_dttm: int | None | Unset = UNSET
    query: None | str | Unset = UNSET
    rejected_filters: list[ChartDataResponseResultRejectedFiltersItem] | Unset = UNSET
    rowcount: int | Unset = UNSET
    stacktrace: None | str | Unset = UNSET
    status: ChartDataResponseResultStatus | Unset = UNSET
    to_dttm: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cache_key: None | str
        cache_key = self.cache_key

        cache_timeout: int | None
        cache_timeout = self.cache_timeout

        cached_dttm: None | str
        cached_dttm = self.cached_dttm

        is_cached = self.is_cached

        annotation_data: list[dict[str, Any]] | None | Unset
        if isinstance(self.annotation_data, Unset):
            annotation_data = UNSET
        elif isinstance(self.annotation_data, list):
            annotation_data = []
            for annotation_data_type_0_item_data in self.annotation_data:
                annotation_data_type_0_item = annotation_data_type_0_item_data.to_dict()
                annotation_data.append(annotation_data_type_0_item)

        else:
            annotation_data = self.annotation_data

        applied_filters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.applied_filters, Unset):
            applied_filters = []
            for applied_filters_item_data in self.applied_filters:
                applied_filters_item = applied_filters_item_data.to_dict()
                applied_filters.append(applied_filters_item)

        colnames: list[str] | Unset = UNSET
        if not isinstance(self.colnames, Unset):
            colnames = self.colnames

        coltypes: list[int] | Unset = UNSET
        if not isinstance(self.coltypes, Unset):
            coltypes = self.coltypes

        data: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.data, Unset):
            data = []
            for data_item_data in self.data:
                data_item = data_item_data.to_dict()
                data.append(data_item)

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        from_dttm: int | None | Unset
        if isinstance(self.from_dttm, Unset):
            from_dttm = UNSET
        else:
            from_dttm = self.from_dttm

        query: None | str | Unset
        if isinstance(self.query, Unset):
            query = UNSET
        else:
            query = self.query

        rejected_filters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.rejected_filters, Unset):
            rejected_filters = []
            for rejected_filters_item_data in self.rejected_filters:
                rejected_filters_item = rejected_filters_item_data.to_dict()
                rejected_filters.append(rejected_filters_item)

        rowcount = self.rowcount

        stacktrace: None | str | Unset
        if isinstance(self.stacktrace, Unset):
            stacktrace = UNSET
        else:
            stacktrace = self.stacktrace

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status

        to_dttm: int | None | Unset
        if isinstance(self.to_dttm, Unset):
            to_dttm = UNSET
        else:
            to_dttm = self.to_dttm

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cache_key": cache_key,
                "cache_timeout": cache_timeout,
                "cached_dttm": cached_dttm,
                "is_cached": is_cached,
            }
        )
        if annotation_data is not UNSET:
            field_dict["annotation_data"] = annotation_data
        if applied_filters is not UNSET:
            field_dict["applied_filters"] = applied_filters
        if colnames is not UNSET:
            field_dict["colnames"] = colnames
        if coltypes is not UNSET:
            field_dict["coltypes"] = coltypes
        if data is not UNSET:
            field_dict["data"] = data
        if error is not UNSET:
            field_dict["error"] = error
        if from_dttm is not UNSET:
            field_dict["from_dttm"] = from_dttm
        if query is not UNSET:
            field_dict["query"] = query
        if rejected_filters is not UNSET:
            field_dict["rejected_filters"] = rejected_filters
        if rowcount is not UNSET:
            field_dict["rowcount"] = rowcount
        if stacktrace is not UNSET:
            field_dict["stacktrace"] = stacktrace
        if status is not UNSET:
            field_dict["status"] = status
        if to_dttm is not UNSET:
            field_dict["to_dttm"] = to_dttm

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_response_result_annotation_data_type_0_item import (
            ChartDataResponseResultAnnotationDataType0Item,
        )
        from ..models.chart_data_response_result_applied_filters_item import ChartDataResponseResultAppliedFiltersItem
        from ..models.chart_data_response_result_data_item import ChartDataResponseResultDataItem
        from ..models.chart_data_response_result_rejected_filters_item import ChartDataResponseResultRejectedFiltersItem

        d = dict(src_dict)

        def _parse_cache_key(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        cache_key = _parse_cache_key(d.pop("cache_key"))

        def _parse_cache_timeout(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        cache_timeout = _parse_cache_timeout(d.pop("cache_timeout"))

        def _parse_cached_dttm(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        cached_dttm = _parse_cached_dttm(d.pop("cached_dttm"))

        is_cached = d.pop("is_cached")

        def _parse_annotation_data(data: object) -> list[ChartDataResponseResultAnnotationDataType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                annotation_data_type_0 = []
                _annotation_data_type_0 = data
                for annotation_data_type_0_item_data in _annotation_data_type_0:
                    annotation_data_type_0_item = ChartDataResponseResultAnnotationDataType0Item.from_dict(
                        annotation_data_type_0_item_data
                    )

                    annotation_data_type_0.append(annotation_data_type_0_item)

                return annotation_data_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[ChartDataResponseResultAnnotationDataType0Item] | None | Unset, data)

        annotation_data = _parse_annotation_data(d.pop("annotation_data", UNSET))

        _applied_filters = d.pop("applied_filters", UNSET)
        applied_filters: list[ChartDataResponseResultAppliedFiltersItem] | Unset = UNSET
        if _applied_filters is not UNSET:
            applied_filters = []
            for applied_filters_item_data in _applied_filters:
                applied_filters_item = ChartDataResponseResultAppliedFiltersItem.from_dict(applied_filters_item_data)

                applied_filters.append(applied_filters_item)

        colnames = cast(list[str], d.pop("colnames", UNSET))

        coltypes = cast(list[int], d.pop("coltypes", UNSET))

        _data = d.pop("data", UNSET)
        data: list[ChartDataResponseResultDataItem] | Unset = UNSET
        if _data is not UNSET:
            data = []
            for data_item_data in _data:
                data_item = ChartDataResponseResultDataItem.from_dict(data_item_data)

                data.append(data_item)

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        def _parse_from_dttm(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        from_dttm = _parse_from_dttm(d.pop("from_dttm", UNSET))

        def _parse_query(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        query = _parse_query(d.pop("query", UNSET))

        _rejected_filters = d.pop("rejected_filters", UNSET)
        rejected_filters: list[ChartDataResponseResultRejectedFiltersItem] | Unset = UNSET
        if _rejected_filters is not UNSET:
            rejected_filters = []
            for rejected_filters_item_data in _rejected_filters:
                rejected_filters_item = ChartDataResponseResultRejectedFiltersItem.from_dict(rejected_filters_item_data)

                rejected_filters.append(rejected_filters_item)

        rowcount = d.pop("rowcount", UNSET)

        def _parse_stacktrace(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stacktrace = _parse_stacktrace(d.pop("stacktrace", UNSET))

        _status = d.pop("status", UNSET)
        status: ChartDataResponseResultStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = check_chart_data_response_result_status(_status)

        def _parse_to_dttm(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        to_dttm = _parse_to_dttm(d.pop("to_dttm", UNSET))

        chart_data_response_result = cls(
            cache_key=cache_key,
            cache_timeout=cache_timeout,
            cached_dttm=cached_dttm,
            is_cached=is_cached,
            annotation_data=annotation_data,
            applied_filters=applied_filters,
            colnames=colnames,
            coltypes=coltypes,
            data=data,
            error=error,
            from_dttm=from_dttm,
            query=query,
            rejected_filters=rejected_filters,
            rowcount=rowcount,
            stacktrace=stacktrace,
            status=status,
            to_dttm=to_dttm,
        )

        chart_data_response_result.additional_properties = d
        return chart_data_response_result

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

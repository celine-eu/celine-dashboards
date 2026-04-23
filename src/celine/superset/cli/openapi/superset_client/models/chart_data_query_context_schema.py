from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_query_context_schema_result_format import (
    ChartDataQueryContextSchemaResultFormat,
    check_chart_data_query_context_schema_result_format,
)
from ..models.chart_data_query_context_schema_result_type import (
    ChartDataQueryContextSchemaResultType,
    check_chart_data_query_context_schema_result_type,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_datasource import ChartDataDatasource
    from ..models.chart_data_query_object import ChartDataQueryObject


T = TypeVar("T", bound="ChartDataQueryContextSchema")


@_attrs_define
class ChartDataQueryContextSchema:
    """
    Attributes:
        custom_cache_timeout (int | None | Unset): Override the default cache timeout
        datasource (ChartDataDatasource | Unset):
        force (bool | None | Unset): Should the queries be forced to load from the source. Default: `false`
        form_data (Any | Unset):
        queries (list[ChartDataQueryObject] | Unset):
        result_format (ChartDataQueryContextSchemaResultFormat | Unset):
        result_type (ChartDataQueryContextSchemaResultType | Unset):
    """

    custom_cache_timeout: int | None | Unset = UNSET
    datasource: ChartDataDatasource | Unset = UNSET
    force: bool | None | Unset = UNSET
    form_data: Any | Unset = UNSET
    queries: list[ChartDataQueryObject] | Unset = UNSET
    result_format: ChartDataQueryContextSchemaResultFormat | Unset = UNSET
    result_type: ChartDataQueryContextSchemaResultType | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        custom_cache_timeout: int | None | Unset
        if isinstance(self.custom_cache_timeout, Unset):
            custom_cache_timeout = UNSET
        else:
            custom_cache_timeout = self.custom_cache_timeout

        datasource: dict[str, Any] | Unset = UNSET
        if not isinstance(self.datasource, Unset):
            datasource = self.datasource.to_dict()

        force: bool | None | Unset
        if isinstance(self.force, Unset):
            force = UNSET
        else:
            force = self.force

        form_data = self.form_data

        queries: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.queries, Unset):
            queries = []
            for queries_item_data in self.queries:
                queries_item = queries_item_data.to_dict()
                queries.append(queries_item)

        result_format: str | Unset = UNSET
        if not isinstance(self.result_format, Unset):
            result_format = self.result_format

        result_type: str | Unset = UNSET
        if not isinstance(self.result_type, Unset):
            result_type = self.result_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if custom_cache_timeout is not UNSET:
            field_dict["custom_cache_timeout"] = custom_cache_timeout
        if datasource is not UNSET:
            field_dict["datasource"] = datasource
        if force is not UNSET:
            field_dict["force"] = force
        if form_data is not UNSET:
            field_dict["form_data"] = form_data
        if queries is not UNSET:
            field_dict["queries"] = queries
        if result_format is not UNSET:
            field_dict["result_format"] = result_format
        if result_type is not UNSET:
            field_dict["result_type"] = result_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_datasource import ChartDataDatasource
        from ..models.chart_data_query_object import ChartDataQueryObject

        d = dict(src_dict)

        def _parse_custom_cache_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        custom_cache_timeout = _parse_custom_cache_timeout(d.pop("custom_cache_timeout", UNSET))

        _datasource = d.pop("datasource", UNSET)
        datasource: ChartDataDatasource | Unset
        if isinstance(_datasource, Unset):
            datasource = UNSET
        else:
            datasource = ChartDataDatasource.from_dict(_datasource)

        def _parse_force(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        force = _parse_force(d.pop("force", UNSET))

        form_data = d.pop("form_data", UNSET)

        _queries = d.pop("queries", UNSET)
        queries: list[ChartDataQueryObject] | Unset = UNSET
        if _queries is not UNSET:
            queries = []
            for queries_item_data in _queries:
                queries_item = ChartDataQueryObject.from_dict(queries_item_data)

                queries.append(queries_item)

        _result_format = d.pop("result_format", UNSET)
        result_format: ChartDataQueryContextSchemaResultFormat | Unset
        if isinstance(_result_format, Unset):
            result_format = UNSET
        else:
            result_format = check_chart_data_query_context_schema_result_format(_result_format)

        _result_type = d.pop("result_type", UNSET)
        result_type: ChartDataQueryContextSchemaResultType | Unset
        if isinstance(_result_type, Unset):
            result_type = UNSET
        else:
            result_type = check_chart_data_query_context_schema_result_type(_result_type)

        chart_data_query_context_schema = cls(
            custom_cache_timeout=custom_cache_timeout,
            datasource=datasource,
            force=force,
            form_data=form_data,
            queries=queries,
            result_format=result_format,
            result_type=result_type,
        )

        chart_data_query_context_schema.additional_properties = d
        return chart_data_query_context_schema

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.chart_data_rest_api_post_datasource_type import (
    ChartDataRestApiPostDatasourceType,
    check_chart_data_rest_api_post_datasource_type,
)
from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataRestApiPost")


@_attrs_define
class ChartDataRestApiPost:
    """
    Attributes:
        datasource_id (int): The id of the dataset/datasource this new chart will use. A complete datasource
            identification needs `datasource_id` and `datasource_type`.
        datasource_type (ChartDataRestApiPostDatasourceType): The type of dataset/datasource identified on
            `datasource_id`.
        slice_name (str): The name of the chart.
        cache_timeout (int | None | Unset): Duration (in seconds) of the caching timeout for this chart. Note this
            defaults to the datasource/table timeout if undefined.
        certification_details (None | str | Unset): Details of the certification
        certified_by (None | str | Unset): Person or group that has certified this chart
        dashboards (list[int] | Unset):
        datasource_name (None | str | Unset): The datasource name.
        description (None | str | Unset): A description of the chart propose.
        external_url (None | str | Unset):
        is_managed_externally (bool | None | Unset):
        owners (list[int] | Unset):
        params (None | str | Unset): Parameters are generated dynamically when clicking the save or overwrite button in
            the explore view. This JSON object for power users who may want to alter specific parameters.
        query_context (None | str | Unset): The query context represents the queries that need to run in order to
            generate the data the visualization, and in what format the data should be returned.
        query_context_generation (bool | None | Unset): The query context generation represents whether the
            query_contextis user generated or not so that it does not update user modifiedstate.
        uuid (None | Unset | UUID):
        viz_type (str | Unset): The type of chart visualization used. Example: ['bar', 'area', 'table'].
    """

    datasource_id: int
    datasource_type: ChartDataRestApiPostDatasourceType
    slice_name: str
    cache_timeout: int | None | Unset = UNSET
    certification_details: None | str | Unset = UNSET
    certified_by: None | str | Unset = UNSET
    dashboards: list[int] | Unset = UNSET
    datasource_name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    external_url: None | str | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    owners: list[int] | Unset = UNSET
    params: None | str | Unset = UNSET
    query_context: None | str | Unset = UNSET
    query_context_generation: bool | None | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    viz_type: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        datasource_id = self.datasource_id

        datasource_type: str = self.datasource_type

        slice_name = self.slice_name

        cache_timeout: int | None | Unset
        if isinstance(self.cache_timeout, Unset):
            cache_timeout = UNSET
        else:
            cache_timeout = self.cache_timeout

        certification_details: None | str | Unset
        if isinstance(self.certification_details, Unset):
            certification_details = UNSET
        else:
            certification_details = self.certification_details

        certified_by: None | str | Unset
        if isinstance(self.certified_by, Unset):
            certified_by = UNSET
        else:
            certified_by = self.certified_by

        dashboards: list[int] | Unset = UNSET
        if not isinstance(self.dashboards, Unset):
            dashboards = self.dashboards

        datasource_name: None | str | Unset
        if isinstance(self.datasource_name, Unset):
            datasource_name = UNSET
        else:
            datasource_name = self.datasource_name

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

        is_managed_externally: bool | None | Unset
        if isinstance(self.is_managed_externally, Unset):
            is_managed_externally = UNSET
        else:
            is_managed_externally = self.is_managed_externally

        owners: list[int] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners

        params: None | str | Unset
        if isinstance(self.params, Unset):
            params = UNSET
        else:
            params = self.params

        query_context: None | str | Unset
        if isinstance(self.query_context, Unset):
            query_context = UNSET
        else:
            query_context = self.query_context

        query_context_generation: bool | None | Unset
        if isinstance(self.query_context_generation, Unset):
            query_context_generation = UNSET
        else:
            query_context_generation = self.query_context_generation

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        viz_type = self.viz_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "datasource_id": datasource_id,
                "datasource_type": datasource_type,
                "slice_name": slice_name,
            }
        )
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if certification_details is not UNSET:
            field_dict["certification_details"] = certification_details
        if certified_by is not UNSET:
            field_dict["certified_by"] = certified_by
        if dashboards is not UNSET:
            field_dict["dashboards"] = dashboards
        if datasource_name is not UNSET:
            field_dict["datasource_name"] = datasource_name
        if description is not UNSET:
            field_dict["description"] = description
        if external_url is not UNSET:
            field_dict["external_url"] = external_url
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if owners is not UNSET:
            field_dict["owners"] = owners
        if params is not UNSET:
            field_dict["params"] = params
        if query_context is not UNSET:
            field_dict["query_context"] = query_context
        if query_context_generation is not UNSET:
            field_dict["query_context_generation"] = query_context_generation
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if viz_type is not UNSET:
            field_dict["viz_type"] = viz_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        datasource_id = d.pop("datasource_id")

        datasource_type = check_chart_data_rest_api_post_datasource_type(d.pop("datasource_type"))

        slice_name = d.pop("slice_name")

        def _parse_cache_timeout(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cache_timeout = _parse_cache_timeout(d.pop("cache_timeout", UNSET))

        def _parse_certification_details(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        certification_details = _parse_certification_details(d.pop("certification_details", UNSET))

        def _parse_certified_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        certified_by = _parse_certified_by(d.pop("certified_by", UNSET))

        dashboards = cast(list[int], d.pop("dashboards", UNSET))

        def _parse_datasource_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        datasource_name = _parse_datasource_name(d.pop("datasource_name", UNSET))

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

        def _parse_is_managed_externally(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_managed_externally = _parse_is_managed_externally(d.pop("is_managed_externally", UNSET))

        owners = cast(list[int], d.pop("owners", UNSET))

        def _parse_params(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        params = _parse_params(d.pop("params", UNSET))

        def _parse_query_context(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        query_context = _parse_query_context(d.pop("query_context", UNSET))

        def _parse_query_context_generation(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        query_context_generation = _parse_query_context_generation(d.pop("query_context_generation", UNSET))

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

        viz_type = d.pop("viz_type", UNSET)

        chart_data_rest_api_post = cls(
            datasource_id=datasource_id,
            datasource_type=datasource_type,
            slice_name=slice_name,
            cache_timeout=cache_timeout,
            certification_details=certification_details,
            certified_by=certified_by,
            dashboards=dashboards,
            datasource_name=datasource_name,
            description=description,
            external_url=external_url,
            is_managed_externally=is_managed_externally,
            owners=owners,
            params=params,
            query_context=query_context,
            query_context_generation=query_context_generation,
            uuid=uuid,
            viz_type=viz_type,
        )

        chart_data_rest_api_post.additional_properties = d
        return chart_data_rest_api_post

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

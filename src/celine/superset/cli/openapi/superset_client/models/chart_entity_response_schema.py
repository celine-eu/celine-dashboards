from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_entity_response_schema_form_data import ChartEntityResponseSchemaFormData


T = TypeVar("T", bound="ChartEntityResponseSchema")


@_attrs_define
class ChartEntityResponseSchema:
    """
    Attributes:
        cache_timeout (int | Unset): Duration (in seconds) of the caching timeout for this chart. Note this defaults to
            the datasource/table timeout if undefined.
        certification_details (str | Unset): Details of the certification
        certified_by (str | Unset): Person or group that has certified this chart
        changed_on (datetime.datetime | Unset): The ISO date that the chart was last changed.
        description (str | Unset): A description of the chart propose.
        description_markeddown (str | Unset): Sanitized HTML version of the chart description.
        form_data (ChartEntityResponseSchemaFormData | Unset): Form data from the Explore controls used to form the
            chart's data query.
        id (int | Unset): The id of the chart.
        slice_name (str | Unset): The name of the chart.
        slice_url (str | Unset): The URL of the chart.
    """

    cache_timeout: int | Unset = UNSET
    certification_details: str | Unset = UNSET
    certified_by: str | Unset = UNSET
    changed_on: datetime.datetime | Unset = UNSET
    description: str | Unset = UNSET
    description_markeddown: str | Unset = UNSET
    form_data: ChartEntityResponseSchemaFormData | Unset = UNSET
    id: int | Unset = UNSET
    slice_name: str | Unset = UNSET
    slice_url: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cache_timeout = self.cache_timeout

        certification_details = self.certification_details

        certified_by = self.certified_by

        changed_on: str | Unset = UNSET
        if not isinstance(self.changed_on, Unset):
            changed_on = self.changed_on.isoformat()

        description = self.description

        description_markeddown = self.description_markeddown

        form_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.form_data, Unset):
            form_data = self.form_data.to_dict()

        id = self.id

        slice_name = self.slice_name

        slice_url = self.slice_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if certification_details is not UNSET:
            field_dict["certification_details"] = certification_details
        if certified_by is not UNSET:
            field_dict["certified_by"] = certified_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if description is not UNSET:
            field_dict["description"] = description
        if description_markeddown is not UNSET:
            field_dict["description_markeddown"] = description_markeddown
        if form_data is not UNSET:
            field_dict["form_data"] = form_data
        if id is not UNSET:
            field_dict["id"] = id
        if slice_name is not UNSET:
            field_dict["slice_name"] = slice_name
        if slice_url is not UNSET:
            field_dict["slice_url"] = slice_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_entity_response_schema_form_data import ChartEntityResponseSchemaFormData

        d = dict(src_dict)
        cache_timeout = d.pop("cache_timeout", UNSET)

        certification_details = d.pop("certification_details", UNSET)

        certified_by = d.pop("certified_by", UNSET)

        _changed_on = d.pop("changed_on", UNSET)
        changed_on: datetime.datetime | Unset
        if isinstance(_changed_on, Unset):
            changed_on = UNSET
        else:
            changed_on = isoparse(_changed_on)

        description = d.pop("description", UNSET)

        description_markeddown = d.pop("description_markeddown", UNSET)

        _form_data = d.pop("form_data", UNSET)
        form_data: ChartEntityResponseSchemaFormData | Unset
        if isinstance(_form_data, Unset):
            form_data = UNSET
        else:
            form_data = ChartEntityResponseSchemaFormData.from_dict(_form_data)

        id = d.pop("id", UNSET)

        slice_name = d.pop("slice_name", UNSET)

        slice_url = d.pop("slice_url", UNSET)

        chart_entity_response_schema = cls(
            cache_timeout=cache_timeout,
            certification_details=certification_details,
            certified_by=certified_by,
            changed_on=changed_on,
            description=description,
            description_markeddown=description_markeddown,
            form_data=form_data,
            id=id,
            slice_name=slice_name,
            slice_url=slice_url,
        )

        chart_entity_response_schema.additional_properties = d
        return chart_entity_response_schema

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

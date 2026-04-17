from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.slice_form_data import SliceFormData
    from ..models.slice_query_context import SliceQueryContext


T = TypeVar("T", bound="Slice")


@_attrs_define
class Slice:
    """
    Attributes:
        cache_timeout (int | Unset): Duration (in seconds) of the caching timeout for this chart.
        certification_details (str | Unset): Details of the certification.
        certified_by (str | Unset): Person or group that has certified this dashboard.
        changed_on (datetime.datetime | Unset): Timestamp of the last modification.
        changed_on_humanized (str | Unset): Timestamp of the last modification in human readable form.
        datasource (str | Unset): Datasource identifier.
        description (str | Unset): Slice description.
        description_markeddown (str | Unset): Sanitized HTML version of the chart description.
        edit_url (str | Unset): The URL for editing the slice.
        form_data (SliceFormData | Unset): Form data associated with the slice.
        is_managed_externally (bool | Unset): If the chart is managed outside externally.
        modified (str | Unset): Last modification in human readable form.
        owners (list[int] | Unset): Owners identifiers.
        query_context (SliceQueryContext | Unset): The context associated with the query.
        slice_id (int | Unset): The slice ID.
        slice_name (str | Unset): The slice name.
        slice_url (str | Unset): The slice URL.
    """

    cache_timeout: int | Unset = UNSET
    certification_details: str | Unset = UNSET
    certified_by: str | Unset = UNSET
    changed_on: datetime.datetime | Unset = UNSET
    changed_on_humanized: str | Unset = UNSET
    datasource: str | Unset = UNSET
    description: str | Unset = UNSET
    description_markeddown: str | Unset = UNSET
    edit_url: str | Unset = UNSET
    form_data: SliceFormData | Unset = UNSET
    is_managed_externally: bool | Unset = UNSET
    modified: str | Unset = UNSET
    owners: list[int] | Unset = UNSET
    query_context: SliceQueryContext | Unset = UNSET
    slice_id: int | Unset = UNSET
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

        changed_on_humanized = self.changed_on_humanized

        datasource = self.datasource

        description = self.description

        description_markeddown = self.description_markeddown

        edit_url = self.edit_url

        form_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.form_data, Unset):
            form_data = self.form_data.to_dict()

        is_managed_externally = self.is_managed_externally

        modified = self.modified

        owners: list[int] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners

        query_context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.query_context, Unset):
            query_context = self.query_context.to_dict()

        slice_id = self.slice_id

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
        if changed_on_humanized is not UNSET:
            field_dict["changed_on_humanized"] = changed_on_humanized
        if datasource is not UNSET:
            field_dict["datasource"] = datasource
        if description is not UNSET:
            field_dict["description"] = description
        if description_markeddown is not UNSET:
            field_dict["description_markeddown"] = description_markeddown
        if edit_url is not UNSET:
            field_dict["edit_url"] = edit_url
        if form_data is not UNSET:
            field_dict["form_data"] = form_data
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if modified is not UNSET:
            field_dict["modified"] = modified
        if owners is not UNSET:
            field_dict["owners"] = owners
        if query_context is not UNSET:
            field_dict["query_context"] = query_context
        if slice_id is not UNSET:
            field_dict["slice_id"] = slice_id
        if slice_name is not UNSET:
            field_dict["slice_name"] = slice_name
        if slice_url is not UNSET:
            field_dict["slice_url"] = slice_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.slice_form_data import SliceFormData
        from ..models.slice_query_context import SliceQueryContext

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

        changed_on_humanized = d.pop("changed_on_humanized", UNSET)

        datasource = d.pop("datasource", UNSET)

        description = d.pop("description", UNSET)

        description_markeddown = d.pop("description_markeddown", UNSET)

        edit_url = d.pop("edit_url", UNSET)

        _form_data = d.pop("form_data", UNSET)
        form_data: SliceFormData | Unset
        if isinstance(_form_data, Unset):
            form_data = UNSET
        else:
            form_data = SliceFormData.from_dict(_form_data)

        is_managed_externally = d.pop("is_managed_externally", UNSET)

        modified = d.pop("modified", UNSET)

        owners = cast(list[int], d.pop("owners", UNSET))

        _query_context = d.pop("query_context", UNSET)
        query_context: SliceQueryContext | Unset
        if isinstance(_query_context, Unset):
            query_context = UNSET
        else:
            query_context = SliceQueryContext.from_dict(_query_context)

        slice_id = d.pop("slice_id", UNSET)

        slice_name = d.pop("slice_name", UNSET)

        slice_url = d.pop("slice_url", UNSET)

        slice_ = cls(
            cache_timeout=cache_timeout,
            certification_details=certification_details,
            certified_by=certified_by,
            changed_on=changed_on,
            changed_on_humanized=changed_on_humanized,
            datasource=datasource,
            description=description,
            description_markeddown=description_markeddown,
            edit_url=edit_url,
            form_data=form_data,
            is_managed_externally=is_managed_externally,
            modified=modified,
            owners=owners,
            query_context=query_context,
            slice_id=slice_id,
            slice_name=slice_name,
            slice_url=slice_url,
        )

        slice_.additional_properties = d
        return slice_

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

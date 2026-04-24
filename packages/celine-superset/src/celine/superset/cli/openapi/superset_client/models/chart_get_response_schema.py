from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dashboard import Dashboard
    from ..models.tag import Tag
    from ..models.user import User


T = TypeVar("T", bound="ChartGetResponseSchema")


@_attrs_define
class ChartGetResponseSchema:
    """
    Attributes:
        cache_timeout (str | Unset):
        certification_details (str | Unset):
        certified_by (str | Unset):
        changed_on_delta_humanized (str | Unset):
        dashboards (list[Dashboard] | Unset):
        datasource_id (int | Unset):
        datasource_name_text (Any | Unset):
        datasource_type (str | Unset):
        datasource_url (Any | Unset):
        datasource_uuid (UUID | Unset):
        description (str | Unset):
        id (int | Unset): The id of the chart.
        is_managed_externally (bool | Unset):
        owners (list[User] | Unset):
        params (str | Unset):
        query_context (str | Unset):
        slice_name (str | Unset):
        tags (list[Tag] | Unset):
        thumbnail_url (str | Unset):
        url (str | Unset):
        uuid (UUID | Unset):
        viz_type (str | Unset):
    """

    cache_timeout: str | Unset = UNSET
    certification_details: str | Unset = UNSET
    certified_by: str | Unset = UNSET
    changed_on_delta_humanized: str | Unset = UNSET
    dashboards: list[Dashboard] | Unset = UNSET
    datasource_id: int | Unset = UNSET
    datasource_name_text: Any | Unset = UNSET
    datasource_type: str | Unset = UNSET
    datasource_url: Any | Unset = UNSET
    datasource_uuid: UUID | Unset = UNSET
    description: str | Unset = UNSET
    id: int | Unset = UNSET
    is_managed_externally: bool | Unset = UNSET
    owners: list[User] | Unset = UNSET
    params: str | Unset = UNSET
    query_context: str | Unset = UNSET
    slice_name: str | Unset = UNSET
    tags: list[Tag] | Unset = UNSET
    thumbnail_url: str | Unset = UNSET
    url: str | Unset = UNSET
    uuid: UUID | Unset = UNSET
    viz_type: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cache_timeout = self.cache_timeout

        certification_details = self.certification_details

        certified_by = self.certified_by

        changed_on_delta_humanized = self.changed_on_delta_humanized

        dashboards: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.dashboards, Unset):
            dashboards = []
            for dashboards_item_data in self.dashboards:
                dashboards_item = dashboards_item_data.to_dict()
                dashboards.append(dashboards_item)

        datasource_id = self.datasource_id

        datasource_name_text = self.datasource_name_text

        datasource_type = self.datasource_type

        datasource_url = self.datasource_url

        datasource_uuid: str | Unset = UNSET
        if not isinstance(self.datasource_uuid, Unset):
            datasource_uuid = str(self.datasource_uuid)

        description = self.description

        id = self.id

        is_managed_externally = self.is_managed_externally

        owners: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = []
            for owners_item_data in self.owners:
                owners_item = owners_item_data.to_dict()
                owners.append(owners_item)

        params = self.params

        query_context = self.query_context

        slice_name = self.slice_name

        tags: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = []
            for tags_item_data in self.tags:
                tags_item = tags_item_data.to_dict()
                tags.append(tags_item)

        thumbnail_url = self.thumbnail_url

        url = self.url

        uuid: str | Unset = UNSET
        if not isinstance(self.uuid, Unset):
            uuid = str(self.uuid)

        viz_type = self.viz_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cache_timeout is not UNSET:
            field_dict["cache_timeout"] = cache_timeout
        if certification_details is not UNSET:
            field_dict["certification_details"] = certification_details
        if certified_by is not UNSET:
            field_dict["certified_by"] = certified_by
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if dashboards is not UNSET:
            field_dict["dashboards"] = dashboards
        if datasource_id is not UNSET:
            field_dict["datasource_id"] = datasource_id
        if datasource_name_text is not UNSET:
            field_dict["datasource_name_text"] = datasource_name_text
        if datasource_type is not UNSET:
            field_dict["datasource_type"] = datasource_type
        if datasource_url is not UNSET:
            field_dict["datasource_url"] = datasource_url
        if datasource_uuid is not UNSET:
            field_dict["datasource_uuid"] = datasource_uuid
        if description is not UNSET:
            field_dict["description"] = description
        if id is not UNSET:
            field_dict["id"] = id
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if owners is not UNSET:
            field_dict["owners"] = owners
        if params is not UNSET:
            field_dict["params"] = params
        if query_context is not UNSET:
            field_dict["query_context"] = query_context
        if slice_name is not UNSET:
            field_dict["slice_name"] = slice_name
        if tags is not UNSET:
            field_dict["tags"] = tags
        if thumbnail_url is not UNSET:
            field_dict["thumbnail_url"] = thumbnail_url
        if url is not UNSET:
            field_dict["url"] = url
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if viz_type is not UNSET:
            field_dict["viz_type"] = viz_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard import Dashboard
        from ..models.tag import Tag
        from ..models.user import User

        d = dict(src_dict)
        cache_timeout = d.pop("cache_timeout", UNSET)

        certification_details = d.pop("certification_details", UNSET)

        certified_by = d.pop("certified_by", UNSET)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        _dashboards = d.pop("dashboards", UNSET)
        dashboards: list[Dashboard] | Unset = UNSET
        if _dashboards is not UNSET:
            dashboards = []
            for dashboards_item_data in _dashboards:
                dashboards_item = Dashboard.from_dict(dashboards_item_data)

                dashboards.append(dashboards_item)

        datasource_id = d.pop("datasource_id", UNSET)

        datasource_name_text = d.pop("datasource_name_text", UNSET)

        datasource_type = d.pop("datasource_type", UNSET)

        datasource_url = d.pop("datasource_url", UNSET)

        _datasource_uuid = d.pop("datasource_uuid", UNSET)
        datasource_uuid: UUID | Unset
        if isinstance(_datasource_uuid, Unset):
            datasource_uuid = UNSET
        else:
            datasource_uuid = UUID(_datasource_uuid)

        description = d.pop("description", UNSET)

        id = d.pop("id", UNSET)

        is_managed_externally = d.pop("is_managed_externally", UNSET)

        _owners = d.pop("owners", UNSET)
        owners: list[User] | Unset = UNSET
        if _owners is not UNSET:
            owners = []
            for owners_item_data in _owners:
                owners_item = User.from_dict(owners_item_data)

                owners.append(owners_item)

        params = d.pop("params", UNSET)

        query_context = d.pop("query_context", UNSET)

        slice_name = d.pop("slice_name", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: list[Tag] | Unset = UNSET
        if _tags is not UNSET:
            tags = []
            for tags_item_data in _tags:
                tags_item = Tag.from_dict(tags_item_data)

                tags.append(tags_item)

        thumbnail_url = d.pop("thumbnail_url", UNSET)

        url = d.pop("url", UNSET)

        _uuid = d.pop("uuid", UNSET)
        uuid: UUID | Unset
        if isinstance(_uuid, Unset):
            uuid = UNSET
        else:
            uuid = UUID(_uuid)

        viz_type = d.pop("viz_type", UNSET)

        chart_get_response_schema = cls(
            cache_timeout=cache_timeout,
            certification_details=certification_details,
            certified_by=certified_by,
            changed_on_delta_humanized=changed_on_delta_humanized,
            dashboards=dashboards,
            datasource_id=datasource_id,
            datasource_name_text=datasource_name_text,
            datasource_type=datasource_type,
            datasource_url=datasource_url,
            datasource_uuid=datasource_uuid,
            description=description,
            id=id,
            is_managed_externally=is_managed_externally,
            owners=owners,
            params=params,
            query_context=query_context,
            slice_name=slice_name,
            tags=tags,
            thumbnail_url=thumbnail_url,
            url=url,
            uuid=uuid,
            viz_type=viz_type,
        )

        chart_get_response_schema.additional_properties = d
        return chart_get_response_schema

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

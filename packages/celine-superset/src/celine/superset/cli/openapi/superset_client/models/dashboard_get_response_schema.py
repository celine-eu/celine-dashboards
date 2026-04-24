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
    from ..models.roles import Roles
    from ..models.tag_1 import Tag1
    from ..models.theme import Theme
    from ..models.user_1 import User1


T = TypeVar("T", bound="DashboardGetResponseSchema")


@_attrs_define
class DashboardGetResponseSchema:
    """
    Attributes:
        certification_details (str | Unset): Details of the certification
        certified_by (str | Unset): Person or group that has certified this dashboard
        changed_by (User1 | Unset):
        changed_by_name (str | Unset):
        changed_on (datetime.datetime | Unset):
        changed_on_delta_humanized (str | Unset):
        charts (list[str] | Unset):
        created_by (User1 | Unset):
        created_on_delta_humanized (str | Unset):
        css (str | Unset): Override CSS for the dashboard.
        dashboard_title (str | Unset): A title for the dashboard.
        id (int | Unset):
        is_managed_externally (bool | None | Unset):
        json_metadata (str | Unset): This JSON object is generated dynamically when clicking the save or overwrite
            button in the dashboard view. It is exposed here for reference and for power users who may want to alter
            specific parameters.
        owners (list[User1] | Unset):
        position_json (str | Unset): This json object describes the positioning of the widgets in the dashboard. It is
            dynamically generated when adjusting the widgets size and positions by using drag & drop in the dashboard view
        published (bool | Unset):
        roles (list[Roles] | Unset):
        slug (str | Unset):
        tags (list[Tag1] | Unset):
        theme (None | Theme | Unset):
        thumbnail_url (None | str | Unset):
        url (str | Unset):
        uuid (None | Unset | UUID):
    """

    certification_details: str | Unset = UNSET
    certified_by: str | Unset = UNSET
    changed_by: User1 | Unset = UNSET
    changed_by_name: str | Unset = UNSET
    changed_on: datetime.datetime | Unset = UNSET
    changed_on_delta_humanized: str | Unset = UNSET
    charts: list[str] | Unset = UNSET
    created_by: User1 | Unset = UNSET
    created_on_delta_humanized: str | Unset = UNSET
    css: str | Unset = UNSET
    dashboard_title: str | Unset = UNSET
    id: int | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    json_metadata: str | Unset = UNSET
    owners: list[User1] | Unset = UNSET
    position_json: str | Unset = UNSET
    published: bool | Unset = UNSET
    roles: list[Roles] | Unset = UNSET
    slug: str | Unset = UNSET
    tags: list[Tag1] | Unset = UNSET
    theme: None | Theme | Unset = UNSET
    thumbnail_url: None | str | Unset = UNSET
    url: str | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.theme import Theme

        certification_details = self.certification_details

        certified_by = self.certified_by

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_by_name = self.changed_by_name

        changed_on: str | Unset = UNSET
        if not isinstance(self.changed_on, Unset):
            changed_on = self.changed_on.isoformat()

        changed_on_delta_humanized = self.changed_on_delta_humanized

        charts: list[str] | Unset = UNSET
        if not isinstance(self.charts, Unset):
            charts = self.charts

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on_delta_humanized = self.created_on_delta_humanized

        css = self.css

        dashboard_title = self.dashboard_title

        id = self.id

        is_managed_externally: bool | None | Unset
        if isinstance(self.is_managed_externally, Unset):
            is_managed_externally = UNSET
        else:
            is_managed_externally = self.is_managed_externally

        json_metadata = self.json_metadata

        owners: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = []
            for owners_item_data in self.owners:
                owners_item = owners_item_data.to_dict()
                owners.append(owners_item)

        position_json = self.position_json

        published = self.published

        roles: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = []
            for roles_item_data in self.roles:
                roles_item = roles_item_data.to_dict()
                roles.append(roles_item)

        slug = self.slug

        tags: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = []
            for tags_item_data in self.tags:
                tags_item = tags_item_data.to_dict()
                tags.append(tags_item)

        theme: dict[str, Any] | None | Unset
        if isinstance(self.theme, Unset):
            theme = UNSET
        elif isinstance(self.theme, Theme):
            theme = self.theme.to_dict()
        else:
            theme = self.theme

        thumbnail_url: None | str | Unset
        if isinstance(self.thumbnail_url, Unset):
            thumbnail_url = UNSET
        else:
            thumbnail_url = self.thumbnail_url

        url = self.url

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if certification_details is not UNSET:
            field_dict["certification_details"] = certification_details
        if certified_by is not UNSET:
            field_dict["certified_by"] = certified_by
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_by_name is not UNSET:
            field_dict["changed_by_name"] = changed_by_name
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if charts is not UNSET:
            field_dict["charts"] = charts
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on_delta_humanized is not UNSET:
            field_dict["created_on_delta_humanized"] = created_on_delta_humanized
        if css is not UNSET:
            field_dict["css"] = css
        if dashboard_title is not UNSET:
            field_dict["dashboard_title"] = dashboard_title
        if id is not UNSET:
            field_dict["id"] = id
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if json_metadata is not UNSET:
            field_dict["json_metadata"] = json_metadata
        if owners is not UNSET:
            field_dict["owners"] = owners
        if position_json is not UNSET:
            field_dict["position_json"] = position_json
        if published is not UNSET:
            field_dict["published"] = published
        if roles is not UNSET:
            field_dict["roles"] = roles
        if slug is not UNSET:
            field_dict["slug"] = slug
        if tags is not UNSET:
            field_dict["tags"] = tags
        if theme is not UNSET:
            field_dict["theme"] = theme
        if thumbnail_url is not UNSET:
            field_dict["thumbnail_url"] = thumbnail_url
        if url is not UNSET:
            field_dict["url"] = url
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.roles import Roles
        from ..models.tag_1 import Tag1
        from ..models.theme import Theme
        from ..models.user_1 import User1

        d = dict(src_dict)
        certification_details = d.pop("certification_details", UNSET)

        certified_by = d.pop("certified_by", UNSET)

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: User1 | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = User1.from_dict(_changed_by)

        changed_by_name = d.pop("changed_by_name", UNSET)

        _changed_on = d.pop("changed_on", UNSET)
        changed_on: datetime.datetime | Unset
        if isinstance(_changed_on, Unset):
            changed_on = UNSET
        else:
            changed_on = isoparse(_changed_on)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        charts = cast(list[str], d.pop("charts", UNSET))

        _created_by = d.pop("created_by", UNSET)
        created_by: User1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = User1.from_dict(_created_by)

        created_on_delta_humanized = d.pop("created_on_delta_humanized", UNSET)

        css = d.pop("css", UNSET)

        dashboard_title = d.pop("dashboard_title", UNSET)

        id = d.pop("id", UNSET)

        def _parse_is_managed_externally(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_managed_externally = _parse_is_managed_externally(d.pop("is_managed_externally", UNSET))

        json_metadata = d.pop("json_metadata", UNSET)

        _owners = d.pop("owners", UNSET)
        owners: list[User1] | Unset = UNSET
        if _owners is not UNSET:
            owners = []
            for owners_item_data in _owners:
                owners_item = User1.from_dict(owners_item_data)

                owners.append(owners_item)

        position_json = d.pop("position_json", UNSET)

        published = d.pop("published", UNSET)

        _roles = d.pop("roles", UNSET)
        roles: list[Roles] | Unset = UNSET
        if _roles is not UNSET:
            roles = []
            for roles_item_data in _roles:
                roles_item = Roles.from_dict(roles_item_data)

                roles.append(roles_item)

        slug = d.pop("slug", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: list[Tag1] | Unset = UNSET
        if _tags is not UNSET:
            tags = []
            for tags_item_data in _tags:
                tags_item = Tag1.from_dict(tags_item_data)

                tags.append(tags_item)

        def _parse_theme(data: object) -> None | Theme | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                theme_type_1 = Theme.from_dict(data)

                return theme_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Theme | Unset, data)

        theme = _parse_theme(d.pop("theme", UNSET))

        def _parse_thumbnail_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        thumbnail_url = _parse_thumbnail_url(d.pop("thumbnail_url", UNSET))

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

        dashboard_get_response_schema = cls(
            certification_details=certification_details,
            certified_by=certified_by,
            changed_by=changed_by,
            changed_by_name=changed_by_name,
            changed_on=changed_on,
            changed_on_delta_humanized=changed_on_delta_humanized,
            charts=charts,
            created_by=created_by,
            created_on_delta_humanized=created_on_delta_humanized,
            css=css,
            dashboard_title=dashboard_title,
            id=id,
            is_managed_externally=is_managed_externally,
            json_metadata=json_metadata,
            owners=owners,
            position_json=position_json,
            published=published,
            roles=roles,
            slug=slug,
            tags=tags,
            theme=theme,
            thumbnail_url=thumbnail_url,
            url=url,
            uuid=uuid,
        )

        dashboard_get_response_schema.additional_properties = d
        return dashboard_get_response_schema

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

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DashboardRestApiPut")


@_attrs_define
class DashboardRestApiPut:
    """
    Attributes:
        certification_details (None | str | Unset): Details of the certification
        certified_by (None | str | Unset): Person or group that has certified this dashboard
        css (None | str | Unset): Override CSS for the dashboard.
        dashboard_title (None | str | Unset): A title for the dashboard.
        external_url (None | str | Unset):
        is_managed_externally (bool | None | Unset):
        json_metadata (None | str | Unset): This JSON object is generated dynamically when clicking the save or
            overwrite button in the dashboard view. It is exposed here for reference and for power users who may want to
            alter  specific parameters.
        owners (list[int | None] | Unset):
        position_json (None | str | Unset): This json object describes the positioning of the widgets in the dashboard.
            It is dynamically generated when adjusting the widgets size and positions by using drag & drop in the dashboard
            view
        published (bool | None | Unset): Determines whether or not this dashboard is visible in the list of all
            dashboards.
        roles (list[int | None] | Unset):
        slug (None | str | Unset): Unique identifying part for the web address of the dashboard.
        tags (list[int | None] | Unset):
        theme_id (int | None | Unset): Theme ID for the dashboard
        uuid (None | Unset | UUID):
    """

    certification_details: None | str | Unset = UNSET
    certified_by: None | str | Unset = UNSET
    css: None | str | Unset = UNSET
    dashboard_title: None | str | Unset = UNSET
    external_url: None | str | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    json_metadata: None | str | Unset = UNSET
    owners: list[int | None] | Unset = UNSET
    position_json: None | str | Unset = UNSET
    published: bool | None | Unset = UNSET
    roles: list[int | None] | Unset = UNSET
    slug: None | str | Unset = UNSET
    tags: list[int | None] | Unset = UNSET
    theme_id: int | None | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
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

        css: None | str | Unset
        if isinstance(self.css, Unset):
            css = UNSET
        else:
            css = self.css

        dashboard_title: None | str | Unset
        if isinstance(self.dashboard_title, Unset):
            dashboard_title = UNSET
        else:
            dashboard_title = self.dashboard_title

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

        json_metadata: None | str | Unset
        if isinstance(self.json_metadata, Unset):
            json_metadata = UNSET
        else:
            json_metadata = self.json_metadata

        owners: list[int | None] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = []
            for owners_item_data in self.owners:
                owners_item: int | None
                owners_item = owners_item_data
                owners.append(owners_item)

        position_json: None | str | Unset
        if isinstance(self.position_json, Unset):
            position_json = UNSET
        else:
            position_json = self.position_json

        published: bool | None | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        roles: list[int | None] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = []
            for roles_item_data in self.roles:
                roles_item: int | None
                roles_item = roles_item_data
                roles.append(roles_item)

        slug: None | str | Unset
        if isinstance(self.slug, Unset):
            slug = UNSET
        else:
            slug = self.slug

        tags: list[int | None] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = []
            for tags_item_data in self.tags:
                tags_item: int | None
                tags_item = tags_item_data
                tags.append(tags_item)

        theme_id: int | None | Unset
        if isinstance(self.theme_id, Unset):
            theme_id = UNSET
        else:
            theme_id = self.theme_id

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
        if css is not UNSET:
            field_dict["css"] = css
        if dashboard_title is not UNSET:
            field_dict["dashboard_title"] = dashboard_title
        if external_url is not UNSET:
            field_dict["external_url"] = external_url
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
        if theme_id is not UNSET:
            field_dict["theme_id"] = theme_id
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

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

        def _parse_css(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        css = _parse_css(d.pop("css", UNSET))

        def _parse_dashboard_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dashboard_title = _parse_dashboard_title(d.pop("dashboard_title", UNSET))

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

        def _parse_json_metadata(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        json_metadata = _parse_json_metadata(d.pop("json_metadata", UNSET))

        _owners = d.pop("owners", UNSET)
        owners: list[int | None] | Unset = UNSET
        if _owners is not UNSET:
            owners = []
            for owners_item_data in _owners:

                def _parse_owners_item(data: object) -> int | None:
                    if data is None:
                        return data
                    return cast(int | None, data)

                owners_item = _parse_owners_item(owners_item_data)

                owners.append(owners_item)

        def _parse_position_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        position_json = _parse_position_json(d.pop("position_json", UNSET))

        def _parse_published(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        _roles = d.pop("roles", UNSET)
        roles: list[int | None] | Unset = UNSET
        if _roles is not UNSET:
            roles = []
            for roles_item_data in _roles:

                def _parse_roles_item(data: object) -> int | None:
                    if data is None:
                        return data
                    return cast(int | None, data)

                roles_item = _parse_roles_item(roles_item_data)

                roles.append(roles_item)

        def _parse_slug(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        slug = _parse_slug(d.pop("slug", UNSET))

        _tags = d.pop("tags", UNSET)
        tags: list[int | None] | Unset = UNSET
        if _tags is not UNSET:
            tags = []
            for tags_item_data in _tags:

                def _parse_tags_item(data: object) -> int | None:
                    if data is None:
                        return data
                    return cast(int | None, data)

                tags_item = _parse_tags_item(tags_item_data)

                tags.append(tags_item)

        def _parse_theme_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        theme_id = _parse_theme_id(d.pop("theme_id", UNSET))

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

        dashboard_rest_api_put = cls(
            certification_details=certification_details,
            certified_by=certified_by,
            css=css,
            dashboard_title=dashboard_title,
            external_url=external_url,
            is_managed_externally=is_managed_externally,
            json_metadata=json_metadata,
            owners=owners,
            position_json=position_json,
            published=published,
            roles=roles,
            slug=slug,
            tags=tags,
            theme_id=theme_id,
            uuid=uuid,
        )

        dashboard_rest_api_put.additional_properties = d
        return dashboard_rest_api_put

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

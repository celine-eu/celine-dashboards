from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DashboardRestApiPost")


@_attrs_define
class DashboardRestApiPost:
    """
    Attributes:
        certification_details (None | str | Unset): Details of the certification
        certified_by (None | str | Unset): Person or group that has certified this dashboard
        css (str | Unset): Override CSS for the dashboard.
        dashboard_title (None | str | Unset): A title for the dashboard.
        external_url (None | str | Unset):
        is_managed_externally (bool | None | Unset):
        json_metadata (str | Unset): This JSON object is generated dynamically when clicking the save or overwrite
            button in the dashboard view. It is exposed here for reference and for power users who may want to alter
            specific parameters.
        owners (list[int] | Unset):
        position_json (str | Unset): This json object describes the positioning of the widgets in the dashboard. It is
            dynamically generated when adjusting the widgets size and positions by using drag & drop in the dashboard view
        published (bool | Unset): Determines whether or not this dashboard is visible in the list of all dashboards.
        roles (list[int] | Unset):
        slug (None | str | Unset): Unique identifying part for the web address of the dashboard.
        theme_id (int | None | Unset): Theme ID for the dashboard
        uuid (None | Unset | UUID):
    """

    certification_details: None | str | Unset = UNSET
    certified_by: None | str | Unset = UNSET
    css: str | Unset = UNSET
    dashboard_title: None | str | Unset = UNSET
    external_url: None | str | Unset = UNSET
    is_managed_externally: bool | None | Unset = UNSET
    json_metadata: str | Unset = UNSET
    owners: list[int] | Unset = UNSET
    position_json: str | Unset = UNSET
    published: bool | Unset = UNSET
    roles: list[int] | Unset = UNSET
    slug: None | str | Unset = UNSET
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

        json_metadata = self.json_metadata

        owners: list[int] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners

        position_json = self.position_json

        published = self.published

        roles: list[int] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles

        slug: None | str | Unset
        if isinstance(self.slug, Unset):
            slug = UNSET
        else:
            slug = self.slug

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

        css = d.pop("css", UNSET)

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

        json_metadata = d.pop("json_metadata", UNSET)

        owners = cast(list[int], d.pop("owners", UNSET))

        position_json = d.pop("position_json", UNSET)

        published = d.pop("published", UNSET)

        roles = cast(list[int], d.pop("roles", UNSET))

        def _parse_slug(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        slug = _parse_slug(d.pop("slug", UNSET))

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

        dashboard_rest_api_post = cls(
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
            theme_id=theme_id,
            uuid=uuid,
        )

        dashboard_rest_api_post.additional_properties = d
        return dashboard_rest_api_post

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

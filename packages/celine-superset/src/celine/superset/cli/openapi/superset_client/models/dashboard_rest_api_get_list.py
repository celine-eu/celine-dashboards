from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dashboard_rest_api_get_list_role import DashboardRestApiGetListRole
    from ..models.dashboard_rest_api_get_list_tag import DashboardRestApiGetListTag
    from ..models.dashboard_rest_api_get_list_user import DashboardRestApiGetListUser
    from ..models.dashboard_rest_api_get_list_user_1 import DashboardRestApiGetListUser1
    from ..models.dashboard_rest_api_get_list_user_2 import DashboardRestApiGetListUser2


T = TypeVar("T", bound="DashboardRestApiGetList")


@_attrs_define
class DashboardRestApiGetList:
    """
    Attributes:
        certification_details (None | str | Unset):
        certified_by (None | str | Unset):
        changed_by (DashboardRestApiGetListUser | Unset):
        changed_by_name (Any | Unset):
        changed_on_delta_humanized (Any | Unset):
        changed_on_utc (Any | Unset):
        created_by (DashboardRestApiGetListUser1 | Unset):
        created_on_delta_humanized (Any | Unset):
        dashboard_title (None | str | Unset):
        id (int | Unset):
        is_managed_externally (bool | Unset):
        owners (DashboardRestApiGetListUser2 | Unset):
        published (bool | None | Unset):
        roles (DashboardRestApiGetListRole | Unset):
        slug (None | str | Unset):
        status (Any | Unset):
        tags (DashboardRestApiGetListTag | Unset):
        thumbnail_url (Any | Unset):
        url (Any | Unset):
        uuid (None | Unset | UUID):
    """

    certification_details: None | str | Unset = UNSET
    certified_by: None | str | Unset = UNSET
    changed_by: DashboardRestApiGetListUser | Unset = UNSET
    changed_by_name: Any | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    changed_on_utc: Any | Unset = UNSET
    created_by: DashboardRestApiGetListUser1 | Unset = UNSET
    created_on_delta_humanized: Any | Unset = UNSET
    dashboard_title: None | str | Unset = UNSET
    id: int | Unset = UNSET
    is_managed_externally: bool | Unset = UNSET
    owners: DashboardRestApiGetListUser2 | Unset = UNSET
    published: bool | None | Unset = UNSET
    roles: DashboardRestApiGetListRole | Unset = UNSET
    slug: None | str | Unset = UNSET
    status: Any | Unset = UNSET
    tags: DashboardRestApiGetListTag | Unset = UNSET
    thumbnail_url: Any | Unset = UNSET
    url: Any | Unset = UNSET
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

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_by_name = self.changed_by_name

        changed_on_delta_humanized = self.changed_on_delta_humanized

        changed_on_utc = self.changed_on_utc

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on_delta_humanized = self.created_on_delta_humanized

        dashboard_title: None | str | Unset
        if isinstance(self.dashboard_title, Unset):
            dashboard_title = UNSET
        else:
            dashboard_title = self.dashboard_title

        id = self.id

        is_managed_externally = self.is_managed_externally

        owners: dict[str, Any] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners.to_dict()

        published: bool | None | Unset
        if isinstance(self.published, Unset):
            published = UNSET
        else:
            published = self.published

        roles: dict[str, Any] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles.to_dict()

        slug: None | str | Unset
        if isinstance(self.slug, Unset):
            slug = UNSET
        else:
            slug = self.slug

        status = self.status

        tags: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags.to_dict()

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
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if changed_on_utc is not UNSET:
            field_dict["changed_on_utc"] = changed_on_utc
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on_delta_humanized is not UNSET:
            field_dict["created_on_delta_humanized"] = created_on_delta_humanized
        if dashboard_title is not UNSET:
            field_dict["dashboard_title"] = dashboard_title
        if id is not UNSET:
            field_dict["id"] = id
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if owners is not UNSET:
            field_dict["owners"] = owners
        if published is not UNSET:
            field_dict["published"] = published
        if roles is not UNSET:
            field_dict["roles"] = roles
        if slug is not UNSET:
            field_dict["slug"] = slug
        if status is not UNSET:
            field_dict["status"] = status
        if tags is not UNSET:
            field_dict["tags"] = tags
        if thumbnail_url is not UNSET:
            field_dict["thumbnail_url"] = thumbnail_url
        if url is not UNSET:
            field_dict["url"] = url
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard_rest_api_get_list_role import DashboardRestApiGetListRole
        from ..models.dashboard_rest_api_get_list_tag import DashboardRestApiGetListTag
        from ..models.dashboard_rest_api_get_list_user import DashboardRestApiGetListUser
        from ..models.dashboard_rest_api_get_list_user_1 import DashboardRestApiGetListUser1
        from ..models.dashboard_rest_api_get_list_user_2 import DashboardRestApiGetListUser2

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

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: DashboardRestApiGetListUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = DashboardRestApiGetListUser.from_dict(_changed_by)

        changed_by_name = d.pop("changed_by_name", UNSET)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        changed_on_utc = d.pop("changed_on_utc", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: DashboardRestApiGetListUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = DashboardRestApiGetListUser1.from_dict(_created_by)

        created_on_delta_humanized = d.pop("created_on_delta_humanized", UNSET)

        def _parse_dashboard_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dashboard_title = _parse_dashboard_title(d.pop("dashboard_title", UNSET))

        id = d.pop("id", UNSET)

        is_managed_externally = d.pop("is_managed_externally", UNSET)

        _owners = d.pop("owners", UNSET)
        owners: DashboardRestApiGetListUser2 | Unset
        if isinstance(_owners, Unset):
            owners = UNSET
        else:
            owners = DashboardRestApiGetListUser2.from_dict(_owners)

        def _parse_published(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        published = _parse_published(d.pop("published", UNSET))

        _roles = d.pop("roles", UNSET)
        roles: DashboardRestApiGetListRole | Unset
        if isinstance(_roles, Unset):
            roles = UNSET
        else:
            roles = DashboardRestApiGetListRole.from_dict(_roles)

        def _parse_slug(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        slug = _parse_slug(d.pop("slug", UNSET))

        status = d.pop("status", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: DashboardRestApiGetListTag | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = DashboardRestApiGetListTag.from_dict(_tags)

        thumbnail_url = d.pop("thumbnail_url", UNSET)

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

        dashboard_rest_api_get_list = cls(
            certification_details=certification_details,
            certified_by=certified_by,
            changed_by=changed_by,
            changed_by_name=changed_by_name,
            changed_on_delta_humanized=changed_on_delta_humanized,
            changed_on_utc=changed_on_utc,
            created_by=created_by,
            created_on_delta_humanized=created_on_delta_humanized,
            dashboard_title=dashboard_title,
            id=id,
            is_managed_externally=is_managed_externally,
            owners=owners,
            published=published,
            roles=roles,
            slug=slug,
            status=status,
            tags=tags,
            thumbnail_url=thumbnail_url,
            url=url,
            uuid=uuid,
        )

        dashboard_rest_api_get_list.additional_properties = d
        return dashboard_rest_api_get_list

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

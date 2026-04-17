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
    from ..models.chart_rest_api_get_list_dashboard import ChartRestApiGetListDashboard
    from ..models.chart_rest_api_get_list_sqla_table import ChartRestApiGetListSqlaTable
    from ..models.chart_rest_api_get_list_tag import ChartRestApiGetListTag
    from ..models.chart_rest_api_get_list_user import ChartRestApiGetListUser
    from ..models.chart_rest_api_get_list_user_1 import ChartRestApiGetListUser1
    from ..models.chart_rest_api_get_list_user_2 import ChartRestApiGetListUser2
    from ..models.chart_rest_api_get_list_user_3 import ChartRestApiGetListUser3


T = TypeVar("T", bound="ChartRestApiGetList")


@_attrs_define
class ChartRestApiGetList:
    """
    Attributes:
        cache_timeout (int | None | Unset):
        certification_details (None | str | Unset):
        certified_by (None | str | Unset):
        changed_by (ChartRestApiGetListUser | Unset):
        changed_by_name (Any | Unset):
        changed_on_delta_humanized (Any | Unset):
        changed_on_dttm (Any | Unset):
        changed_on_utc (Any | Unset):
        created_by (ChartRestApiGetListUser1 | Unset):
        created_by_name (Any | Unset):
        created_on_delta_humanized (Any | Unset):
        dashboards (ChartRestApiGetListDashboard | Unset):
        datasource_id (int | None | Unset):
        datasource_name_text (Any | Unset):
        datasource_type (None | str | Unset):
        datasource_url (Any | Unset):
        description (None | str | Unset):
        description_markeddown (Any | Unset):
        edit_url (Any | Unset):
        form_data (Any | Unset):
        id (int | Unset):
        is_managed_externally (bool | Unset):
        last_saved_at (datetime.datetime | None | Unset):
        last_saved_by (ChartRestApiGetListUser2 | Unset):
        owners (ChartRestApiGetListUser3 | Unset):
        params (None | str | Unset):
        slice_name (None | str | Unset):
        slice_url (Any | Unset):
        table (ChartRestApiGetListSqlaTable | Unset):
        tags (ChartRestApiGetListTag | Unset):
        thumbnail_url (Any | Unset):
        url (Any | Unset):
        uuid (None | Unset | UUID):
        viz_type (None | str | Unset):
    """

    cache_timeout: int | None | Unset = UNSET
    certification_details: None | str | Unset = UNSET
    certified_by: None | str | Unset = UNSET
    changed_by: ChartRestApiGetListUser | Unset = UNSET
    changed_by_name: Any | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    changed_on_dttm: Any | Unset = UNSET
    changed_on_utc: Any | Unset = UNSET
    created_by: ChartRestApiGetListUser1 | Unset = UNSET
    created_by_name: Any | Unset = UNSET
    created_on_delta_humanized: Any | Unset = UNSET
    dashboards: ChartRestApiGetListDashboard | Unset = UNSET
    datasource_id: int | None | Unset = UNSET
    datasource_name_text: Any | Unset = UNSET
    datasource_type: None | str | Unset = UNSET
    datasource_url: Any | Unset = UNSET
    description: None | str | Unset = UNSET
    description_markeddown: Any | Unset = UNSET
    edit_url: Any | Unset = UNSET
    form_data: Any | Unset = UNSET
    id: int | Unset = UNSET
    is_managed_externally: bool | Unset = UNSET
    last_saved_at: datetime.datetime | None | Unset = UNSET
    last_saved_by: ChartRestApiGetListUser2 | Unset = UNSET
    owners: ChartRestApiGetListUser3 | Unset = UNSET
    params: None | str | Unset = UNSET
    slice_name: None | str | Unset = UNSET
    slice_url: Any | Unset = UNSET
    table: ChartRestApiGetListSqlaTable | Unset = UNSET
    tags: ChartRestApiGetListTag | Unset = UNSET
    thumbnail_url: Any | Unset = UNSET
    url: Any | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    viz_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
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

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_by_name = self.changed_by_name

        changed_on_delta_humanized = self.changed_on_delta_humanized

        changed_on_dttm = self.changed_on_dttm

        changed_on_utc = self.changed_on_utc

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_by_name = self.created_by_name

        created_on_delta_humanized = self.created_on_delta_humanized

        dashboards: dict[str, Any] | Unset = UNSET
        if not isinstance(self.dashboards, Unset):
            dashboards = self.dashboards.to_dict()

        datasource_id: int | None | Unset
        if isinstance(self.datasource_id, Unset):
            datasource_id = UNSET
        else:
            datasource_id = self.datasource_id

        datasource_name_text = self.datasource_name_text

        datasource_type: None | str | Unset
        if isinstance(self.datasource_type, Unset):
            datasource_type = UNSET
        else:
            datasource_type = self.datasource_type

        datasource_url = self.datasource_url

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        description_markeddown = self.description_markeddown

        edit_url = self.edit_url

        form_data = self.form_data

        id = self.id

        is_managed_externally = self.is_managed_externally

        last_saved_at: None | str | Unset
        if isinstance(self.last_saved_at, Unset):
            last_saved_at = UNSET
        elif isinstance(self.last_saved_at, datetime.datetime):
            last_saved_at = self.last_saved_at.isoformat()
        else:
            last_saved_at = self.last_saved_at

        last_saved_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.last_saved_by, Unset):
            last_saved_by = self.last_saved_by.to_dict()

        owners: dict[str, Any] | Unset = UNSET
        if not isinstance(self.owners, Unset):
            owners = self.owners.to_dict()

        params: None | str | Unset
        if isinstance(self.params, Unset):
            params = UNSET
        else:
            params = self.params

        slice_name: None | str | Unset
        if isinstance(self.slice_name, Unset):
            slice_name = UNSET
        else:
            slice_name = self.slice_name

        slice_url = self.slice_url

        table: dict[str, Any] | Unset = UNSET
        if not isinstance(self.table, Unset):
            table = self.table.to_dict()

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

        viz_type: None | str | Unset
        if isinstance(self.viz_type, Unset):
            viz_type = UNSET
        else:
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
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_by_name is not UNSET:
            field_dict["changed_by_name"] = changed_by_name
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if changed_on_dttm is not UNSET:
            field_dict["changed_on_dttm"] = changed_on_dttm
        if changed_on_utc is not UNSET:
            field_dict["changed_on_utc"] = changed_on_utc
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_by_name is not UNSET:
            field_dict["created_by_name"] = created_by_name
        if created_on_delta_humanized is not UNSET:
            field_dict["created_on_delta_humanized"] = created_on_delta_humanized
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
        if description is not UNSET:
            field_dict["description"] = description
        if description_markeddown is not UNSET:
            field_dict["description_markeddown"] = description_markeddown
        if edit_url is not UNSET:
            field_dict["edit_url"] = edit_url
        if form_data is not UNSET:
            field_dict["form_data"] = form_data
        if id is not UNSET:
            field_dict["id"] = id
        if is_managed_externally is not UNSET:
            field_dict["is_managed_externally"] = is_managed_externally
        if last_saved_at is not UNSET:
            field_dict["last_saved_at"] = last_saved_at
        if last_saved_by is not UNSET:
            field_dict["last_saved_by"] = last_saved_by
        if owners is not UNSET:
            field_dict["owners"] = owners
        if params is not UNSET:
            field_dict["params"] = params
        if slice_name is not UNSET:
            field_dict["slice_name"] = slice_name
        if slice_url is not UNSET:
            field_dict["slice_url"] = slice_url
        if table is not UNSET:
            field_dict["table"] = table
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
        from ..models.chart_rest_api_get_list_dashboard import ChartRestApiGetListDashboard
        from ..models.chart_rest_api_get_list_sqla_table import ChartRestApiGetListSqlaTable
        from ..models.chart_rest_api_get_list_tag import ChartRestApiGetListTag
        from ..models.chart_rest_api_get_list_user import ChartRestApiGetListUser
        from ..models.chart_rest_api_get_list_user_1 import ChartRestApiGetListUser1
        from ..models.chart_rest_api_get_list_user_2 import ChartRestApiGetListUser2
        from ..models.chart_rest_api_get_list_user_3 import ChartRestApiGetListUser3

        d = dict(src_dict)

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

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: ChartRestApiGetListUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = ChartRestApiGetListUser.from_dict(_changed_by)

        changed_by_name = d.pop("changed_by_name", UNSET)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        changed_on_dttm = d.pop("changed_on_dttm", UNSET)

        changed_on_utc = d.pop("changed_on_utc", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: ChartRestApiGetListUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = ChartRestApiGetListUser1.from_dict(_created_by)

        created_by_name = d.pop("created_by_name", UNSET)

        created_on_delta_humanized = d.pop("created_on_delta_humanized", UNSET)

        _dashboards = d.pop("dashboards", UNSET)
        dashboards: ChartRestApiGetListDashboard | Unset
        if isinstance(_dashboards, Unset):
            dashboards = UNSET
        else:
            dashboards = ChartRestApiGetListDashboard.from_dict(_dashboards)

        def _parse_datasource_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        datasource_id = _parse_datasource_id(d.pop("datasource_id", UNSET))

        datasource_name_text = d.pop("datasource_name_text", UNSET)

        def _parse_datasource_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        datasource_type = _parse_datasource_type(d.pop("datasource_type", UNSET))

        datasource_url = d.pop("datasource_url", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        description_markeddown = d.pop("description_markeddown", UNSET)

        edit_url = d.pop("edit_url", UNSET)

        form_data = d.pop("form_data", UNSET)

        id = d.pop("id", UNSET)

        is_managed_externally = d.pop("is_managed_externally", UNSET)

        def _parse_last_saved_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_saved_at_type_0 = isoparse(data)

                return last_saved_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_saved_at = _parse_last_saved_at(d.pop("last_saved_at", UNSET))

        _last_saved_by = d.pop("last_saved_by", UNSET)
        last_saved_by: ChartRestApiGetListUser2 | Unset
        if isinstance(_last_saved_by, Unset):
            last_saved_by = UNSET
        else:
            last_saved_by = ChartRestApiGetListUser2.from_dict(_last_saved_by)

        _owners = d.pop("owners", UNSET)
        owners: ChartRestApiGetListUser3 | Unset
        if isinstance(_owners, Unset):
            owners = UNSET
        else:
            owners = ChartRestApiGetListUser3.from_dict(_owners)

        def _parse_params(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        params = _parse_params(d.pop("params", UNSET))

        def _parse_slice_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        slice_name = _parse_slice_name(d.pop("slice_name", UNSET))

        slice_url = d.pop("slice_url", UNSET)

        _table = d.pop("table", UNSET)
        table: ChartRestApiGetListSqlaTable | Unset
        if isinstance(_table, Unset):
            table = UNSET
        else:
            table = ChartRestApiGetListSqlaTable.from_dict(_table)

        _tags = d.pop("tags", UNSET)
        tags: ChartRestApiGetListTag | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = ChartRestApiGetListTag.from_dict(_tags)

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

        def _parse_viz_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        viz_type = _parse_viz_type(d.pop("viz_type", UNSET))

        chart_rest_api_get_list = cls(
            cache_timeout=cache_timeout,
            certification_details=certification_details,
            certified_by=certified_by,
            changed_by=changed_by,
            changed_by_name=changed_by_name,
            changed_on_delta_humanized=changed_on_delta_humanized,
            changed_on_dttm=changed_on_dttm,
            changed_on_utc=changed_on_utc,
            created_by=created_by,
            created_by_name=created_by_name,
            created_on_delta_humanized=created_on_delta_humanized,
            dashboards=dashboards,
            datasource_id=datasource_id,
            datasource_name_text=datasource_name_text,
            datasource_type=datasource_type,
            datasource_url=datasource_url,
            description=description,
            description_markeddown=description_markeddown,
            edit_url=edit_url,
            form_data=form_data,
            id=id,
            is_managed_externally=is_managed_externally,
            last_saved_at=last_saved_at,
            last_saved_by=last_saved_by,
            owners=owners,
            params=params,
            slice_name=slice_name,
            slice_url=slice_url,
            table=table,
            tags=tags,
            thumbnail_url=thumbnail_url,
            url=url,
            uuid=uuid,
            viz_type=viz_type,
        )

        chart_rest_api_get_list.additional_properties = d
        return chart_rest_api_get_list

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

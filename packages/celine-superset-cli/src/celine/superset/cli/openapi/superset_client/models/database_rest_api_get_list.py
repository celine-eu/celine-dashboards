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
    from ..models.database_rest_api_get_list_user import DatabaseRestApiGetListUser
    from ..models.database_rest_api_get_list_user_1 import DatabaseRestApiGetListUser1


T = TypeVar("T", bound="DatabaseRestApiGetList")


@_attrs_define
class DatabaseRestApiGetList:
    """
    Attributes:
        database_name (str):
        allow_ctas (bool | None | Unset):
        allow_cvas (bool | None | Unset):
        allow_dml (bool | None | Unset):
        allow_file_upload (bool | None | Unset):
        allow_multi_catalog (Any | Unset):
        allow_run_async (bool | None | Unset):
        allows_cost_estimate (Any | Unset):
        allows_subquery (Any | Unset):
        allows_virtual_table_explore (Any | Unset):
        backend (Any | Unset):
        changed_by (DatabaseRestApiGetListUser | Unset):
        changed_on (datetime.datetime | None | Unset):
        changed_on_delta_humanized (Any | Unset):
        created_by (DatabaseRestApiGetListUser1 | Unset):
        disable_data_preview (Any | Unset):
        disable_drill_to_detail (Any | Unset):
        engine_information (Any | Unset):
        explore_database_id (Any | Unset):
        expose_in_sqllab (bool | None | Unset):
        extra (None | str | Unset):
        force_ctas_schema (None | str | Unset):
        id (int | Unset):
        uuid (None | Unset | UUID):
    """

    database_name: str
    allow_ctas: bool | None | Unset = UNSET
    allow_cvas: bool | None | Unset = UNSET
    allow_dml: bool | None | Unset = UNSET
    allow_file_upload: bool | None | Unset = UNSET
    allow_multi_catalog: Any | Unset = UNSET
    allow_run_async: bool | None | Unset = UNSET
    allows_cost_estimate: Any | Unset = UNSET
    allows_subquery: Any | Unset = UNSET
    allows_virtual_table_explore: Any | Unset = UNSET
    backend: Any | Unset = UNSET
    changed_by: DatabaseRestApiGetListUser | Unset = UNSET
    changed_on: datetime.datetime | None | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    created_by: DatabaseRestApiGetListUser1 | Unset = UNSET
    disable_data_preview: Any | Unset = UNSET
    disable_drill_to_detail: Any | Unset = UNSET
    engine_information: Any | Unset = UNSET
    explore_database_id: Any | Unset = UNSET
    expose_in_sqllab: bool | None | Unset = UNSET
    extra: None | str | Unset = UNSET
    force_ctas_schema: None | str | Unset = UNSET
    id: int | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        database_name = self.database_name

        allow_ctas: bool | None | Unset
        if isinstance(self.allow_ctas, Unset):
            allow_ctas = UNSET
        else:
            allow_ctas = self.allow_ctas

        allow_cvas: bool | None | Unset
        if isinstance(self.allow_cvas, Unset):
            allow_cvas = UNSET
        else:
            allow_cvas = self.allow_cvas

        allow_dml: bool | None | Unset
        if isinstance(self.allow_dml, Unset):
            allow_dml = UNSET
        else:
            allow_dml = self.allow_dml

        allow_file_upload: bool | None | Unset
        if isinstance(self.allow_file_upload, Unset):
            allow_file_upload = UNSET
        else:
            allow_file_upload = self.allow_file_upload

        allow_multi_catalog = self.allow_multi_catalog

        allow_run_async: bool | None | Unset
        if isinstance(self.allow_run_async, Unset):
            allow_run_async = UNSET
        else:
            allow_run_async = self.allow_run_async

        allows_cost_estimate = self.allows_cost_estimate

        allows_subquery = self.allows_subquery

        allows_virtual_table_explore = self.allows_virtual_table_explore

        backend = self.backend

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        changed_on_delta_humanized = self.changed_on_delta_humanized

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        disable_data_preview = self.disable_data_preview

        disable_drill_to_detail = self.disable_drill_to_detail

        engine_information = self.engine_information

        explore_database_id = self.explore_database_id

        expose_in_sqllab: bool | None | Unset
        if isinstance(self.expose_in_sqllab, Unset):
            expose_in_sqllab = UNSET
        else:
            expose_in_sqllab = self.expose_in_sqllab

        extra: None | str | Unset
        if isinstance(self.extra, Unset):
            extra = UNSET
        else:
            extra = self.extra

        force_ctas_schema: None | str | Unset
        if isinstance(self.force_ctas_schema, Unset):
            force_ctas_schema = UNSET
        else:
            force_ctas_schema = self.force_ctas_schema

        id = self.id

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "database_name": database_name,
            }
        )
        if allow_ctas is not UNSET:
            field_dict["allow_ctas"] = allow_ctas
        if allow_cvas is not UNSET:
            field_dict["allow_cvas"] = allow_cvas
        if allow_dml is not UNSET:
            field_dict["allow_dml"] = allow_dml
        if allow_file_upload is not UNSET:
            field_dict["allow_file_upload"] = allow_file_upload
        if allow_multi_catalog is not UNSET:
            field_dict["allow_multi_catalog"] = allow_multi_catalog
        if allow_run_async is not UNSET:
            field_dict["allow_run_async"] = allow_run_async
        if allows_cost_estimate is not UNSET:
            field_dict["allows_cost_estimate"] = allows_cost_estimate
        if allows_subquery is not UNSET:
            field_dict["allows_subquery"] = allows_subquery
        if allows_virtual_table_explore is not UNSET:
            field_dict["allows_virtual_table_explore"] = allows_virtual_table_explore
        if backend is not UNSET:
            field_dict["backend"] = backend
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if disable_data_preview is not UNSET:
            field_dict["disable_data_preview"] = disable_data_preview
        if disable_drill_to_detail is not UNSET:
            field_dict["disable_drill_to_detail"] = disable_drill_to_detail
        if engine_information is not UNSET:
            field_dict["engine_information"] = engine_information
        if explore_database_id is not UNSET:
            field_dict["explore_database_id"] = explore_database_id
        if expose_in_sqllab is not UNSET:
            field_dict["expose_in_sqllab"] = expose_in_sqllab
        if extra is not UNSET:
            field_dict["extra"] = extra
        if force_ctas_schema is not UNSET:
            field_dict["force_ctas_schema"] = force_ctas_schema
        if id is not UNSET:
            field_dict["id"] = id
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.database_rest_api_get_list_user import DatabaseRestApiGetListUser
        from ..models.database_rest_api_get_list_user_1 import DatabaseRestApiGetListUser1

        d = dict(src_dict)
        database_name = d.pop("database_name")

        def _parse_allow_ctas(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_ctas = _parse_allow_ctas(d.pop("allow_ctas", UNSET))

        def _parse_allow_cvas(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_cvas = _parse_allow_cvas(d.pop("allow_cvas", UNSET))

        def _parse_allow_dml(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_dml = _parse_allow_dml(d.pop("allow_dml", UNSET))

        def _parse_allow_file_upload(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_file_upload = _parse_allow_file_upload(d.pop("allow_file_upload", UNSET))

        allow_multi_catalog = d.pop("allow_multi_catalog", UNSET)

        def _parse_allow_run_async(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_run_async = _parse_allow_run_async(d.pop("allow_run_async", UNSET))

        allows_cost_estimate = d.pop("allows_cost_estimate", UNSET)

        allows_subquery = d.pop("allows_subquery", UNSET)

        allows_virtual_table_explore = d.pop("allows_virtual_table_explore", UNSET)

        backend = d.pop("backend", UNSET)

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: DatabaseRestApiGetListUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = DatabaseRestApiGetListUser.from_dict(_changed_by)

        def _parse_changed_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                changed_on_type_0 = isoparse(data)

                return changed_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        changed_on = _parse_changed_on(d.pop("changed_on", UNSET))

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: DatabaseRestApiGetListUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = DatabaseRestApiGetListUser1.from_dict(_created_by)

        disable_data_preview = d.pop("disable_data_preview", UNSET)

        disable_drill_to_detail = d.pop("disable_drill_to_detail", UNSET)

        engine_information = d.pop("engine_information", UNSET)

        explore_database_id = d.pop("explore_database_id", UNSET)

        def _parse_expose_in_sqllab(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        expose_in_sqllab = _parse_expose_in_sqllab(d.pop("expose_in_sqllab", UNSET))

        def _parse_extra(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extra = _parse_extra(d.pop("extra", UNSET))

        def _parse_force_ctas_schema(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        force_ctas_schema = _parse_force_ctas_schema(d.pop("force_ctas_schema", UNSET))

        id = d.pop("id", UNSET)

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

        database_rest_api_get_list = cls(
            database_name=database_name,
            allow_ctas=allow_ctas,
            allow_cvas=allow_cvas,
            allow_dml=allow_dml,
            allow_file_upload=allow_file_upload,
            allow_multi_catalog=allow_multi_catalog,
            allow_run_async=allow_run_async,
            allows_cost_estimate=allows_cost_estimate,
            allows_subquery=allows_subquery,
            allows_virtual_table_explore=allows_virtual_table_explore,
            backend=backend,
            changed_by=changed_by,
            changed_on=changed_on,
            changed_on_delta_humanized=changed_on_delta_humanized,
            created_by=created_by,
            disable_data_preview=disable_data_preview,
            disable_drill_to_detail=disable_drill_to_detail,
            engine_information=engine_information,
            explore_database_id=explore_database_id,
            expose_in_sqllab=expose_in_sqllab,
            extra=extra,
            force_ctas_schema=force_ctas_schema,
            id=id,
            uuid=uuid,
        )

        database_rest_api_get_list.additional_properties = d
        return database_rest_api_get_list

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

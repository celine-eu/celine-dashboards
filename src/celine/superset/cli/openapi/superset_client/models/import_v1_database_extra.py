from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.import_v1_database_extra_engine_params import ImportV1DatabaseExtraEngineParams
    from ..models.import_v1_database_extra_metadata_cache_timeout import ImportV1DatabaseExtraMetadataCacheTimeout
    from ..models.import_v1_database_extra_metadata_params import ImportV1DatabaseExtraMetadataParams
    from ..models.import_v1_database_extra_schema_options import ImportV1DatabaseExtraSchemaOptions


T = TypeVar("T", bound="ImportV1DatabaseExtra")


@_attrs_define
class ImportV1DatabaseExtra:
    """
    Attributes:
        allow_multi_catalog (bool | Unset):
        allows_virtual_table_explore (bool | Unset):
        cancel_query_on_windows_unload (bool | Unset):
        cost_estimate_enabled (bool | Unset):
        disable_data_preview (bool | Unset):
        disable_drill_to_detail (bool | Unset):
        engine_params (ImportV1DatabaseExtraEngineParams | Unset):
        metadata_cache_timeout (ImportV1DatabaseExtraMetadataCacheTimeout | Unset):
        metadata_params (ImportV1DatabaseExtraMetadataParams | Unset):
        schema_options (ImportV1DatabaseExtraSchemaOptions | Unset):
        schemas_allowed_for_csv_upload (list[str] | Unset):
        version (None | str | Unset):
    """

    allow_multi_catalog: bool | Unset = UNSET
    allows_virtual_table_explore: bool | Unset = UNSET
    cancel_query_on_windows_unload: bool | Unset = UNSET
    cost_estimate_enabled: bool | Unset = UNSET
    disable_data_preview: bool | Unset = UNSET
    disable_drill_to_detail: bool | Unset = UNSET
    engine_params: ImportV1DatabaseExtraEngineParams | Unset = UNSET
    metadata_cache_timeout: ImportV1DatabaseExtraMetadataCacheTimeout | Unset = UNSET
    metadata_params: ImportV1DatabaseExtraMetadataParams | Unset = UNSET
    schema_options: ImportV1DatabaseExtraSchemaOptions | Unset = UNSET
    schemas_allowed_for_csv_upload: list[str] | Unset = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        allow_multi_catalog = self.allow_multi_catalog

        allows_virtual_table_explore = self.allows_virtual_table_explore

        cancel_query_on_windows_unload = self.cancel_query_on_windows_unload

        cost_estimate_enabled = self.cost_estimate_enabled

        disable_data_preview = self.disable_data_preview

        disable_drill_to_detail = self.disable_drill_to_detail

        engine_params: dict[str, Any] | Unset = UNSET
        if not isinstance(self.engine_params, Unset):
            engine_params = self.engine_params.to_dict()

        metadata_cache_timeout: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata_cache_timeout, Unset):
            metadata_cache_timeout = self.metadata_cache_timeout.to_dict()

        metadata_params: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata_params, Unset):
            metadata_params = self.metadata_params.to_dict()

        schema_options: dict[str, Any] | Unset = UNSET
        if not isinstance(self.schema_options, Unset):
            schema_options = self.schema_options.to_dict()

        schemas_allowed_for_csv_upload: list[str] | Unset = UNSET
        if not isinstance(self.schemas_allowed_for_csv_upload, Unset):
            schemas_allowed_for_csv_upload = self.schemas_allowed_for_csv_upload

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if allow_multi_catalog is not UNSET:
            field_dict["allow_multi_catalog"] = allow_multi_catalog
        if allows_virtual_table_explore is not UNSET:
            field_dict["allows_virtual_table_explore"] = allows_virtual_table_explore
        if cancel_query_on_windows_unload is not UNSET:
            field_dict["cancel_query_on_windows_unload"] = cancel_query_on_windows_unload
        if cost_estimate_enabled is not UNSET:
            field_dict["cost_estimate_enabled"] = cost_estimate_enabled
        if disable_data_preview is not UNSET:
            field_dict["disable_data_preview"] = disable_data_preview
        if disable_drill_to_detail is not UNSET:
            field_dict["disable_drill_to_detail"] = disable_drill_to_detail
        if engine_params is not UNSET:
            field_dict["engine_params"] = engine_params
        if metadata_cache_timeout is not UNSET:
            field_dict["metadata_cache_timeout"] = metadata_cache_timeout
        if metadata_params is not UNSET:
            field_dict["metadata_params"] = metadata_params
        if schema_options is not UNSET:
            field_dict["schema_options"] = schema_options
        if schemas_allowed_for_csv_upload is not UNSET:
            field_dict["schemas_allowed_for_csv_upload"] = schemas_allowed_for_csv_upload
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.import_v1_database_extra_engine_params import ImportV1DatabaseExtraEngineParams
        from ..models.import_v1_database_extra_metadata_cache_timeout import ImportV1DatabaseExtraMetadataCacheTimeout
        from ..models.import_v1_database_extra_metadata_params import ImportV1DatabaseExtraMetadataParams
        from ..models.import_v1_database_extra_schema_options import ImportV1DatabaseExtraSchemaOptions

        d = dict(src_dict)
        allow_multi_catalog = d.pop("allow_multi_catalog", UNSET)

        allows_virtual_table_explore = d.pop("allows_virtual_table_explore", UNSET)

        cancel_query_on_windows_unload = d.pop("cancel_query_on_windows_unload", UNSET)

        cost_estimate_enabled = d.pop("cost_estimate_enabled", UNSET)

        disable_data_preview = d.pop("disable_data_preview", UNSET)

        disable_drill_to_detail = d.pop("disable_drill_to_detail", UNSET)

        _engine_params = d.pop("engine_params", UNSET)
        engine_params: ImportV1DatabaseExtraEngineParams | Unset
        if isinstance(_engine_params, Unset):
            engine_params = UNSET
        else:
            engine_params = ImportV1DatabaseExtraEngineParams.from_dict(_engine_params)

        _metadata_cache_timeout = d.pop("metadata_cache_timeout", UNSET)
        metadata_cache_timeout: ImportV1DatabaseExtraMetadataCacheTimeout | Unset
        if isinstance(_metadata_cache_timeout, Unset):
            metadata_cache_timeout = UNSET
        else:
            metadata_cache_timeout = ImportV1DatabaseExtraMetadataCacheTimeout.from_dict(_metadata_cache_timeout)

        _metadata_params = d.pop("metadata_params", UNSET)
        metadata_params: ImportV1DatabaseExtraMetadataParams | Unset
        if isinstance(_metadata_params, Unset):
            metadata_params = UNSET
        else:
            metadata_params = ImportV1DatabaseExtraMetadataParams.from_dict(_metadata_params)

        _schema_options = d.pop("schema_options", UNSET)
        schema_options: ImportV1DatabaseExtraSchemaOptions | Unset
        if isinstance(_schema_options, Unset):
            schema_options = UNSET
        else:
            schema_options = ImportV1DatabaseExtraSchemaOptions.from_dict(_schema_options)

        schemas_allowed_for_csv_upload = cast(list[str], d.pop("schemas_allowed_for_csv_upload", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        import_v1_database_extra = cls(
            allow_multi_catalog=allow_multi_catalog,
            allows_virtual_table_explore=allows_virtual_table_explore,
            cancel_query_on_windows_unload=cancel_query_on_windows_unload,
            cost_estimate_enabled=cost_estimate_enabled,
            disable_data_preview=disable_data_preview,
            disable_drill_to_detail=disable_drill_to_detail,
            engine_params=engine_params,
            metadata_cache_timeout=metadata_cache_timeout,
            metadata_params=metadata_params,
            schema_options=schema_options,
            schemas_allowed_for_csv_upload=schemas_allowed_for_csv_upload,
            version=version,
        )

        import_v1_database_extra.additional_properties = d
        return import_v1_database_extra

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

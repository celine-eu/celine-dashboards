from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.annotation_rest_api_get_annotation_layer import AnnotationRestApiGetAnnotationLayer


T = TypeVar("T", bound="AnnotationRestApiGet")


@_attrs_define
class AnnotationRestApiGet:
    """
    Attributes:
        layer (AnnotationRestApiGetAnnotationLayer):
        end_dttm (datetime.datetime | None | Unset):
        id (int | Unset):
        json_metadata (None | str | Unset):
        long_descr (None | str | Unset):
        short_descr (None | str | Unset):
        start_dttm (datetime.datetime | None | Unset):
    """

    layer: AnnotationRestApiGetAnnotationLayer
    end_dttm: datetime.datetime | None | Unset = UNSET
    id: int | Unset = UNSET
    json_metadata: None | str | Unset = UNSET
    long_descr: None | str | Unset = UNSET
    short_descr: None | str | Unset = UNSET
    start_dttm: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        layer = self.layer.to_dict()

        end_dttm: None | str | Unset
        if isinstance(self.end_dttm, Unset):
            end_dttm = UNSET
        elif isinstance(self.end_dttm, datetime.datetime):
            end_dttm = self.end_dttm.isoformat()
        else:
            end_dttm = self.end_dttm

        id = self.id

        json_metadata: None | str | Unset
        if isinstance(self.json_metadata, Unset):
            json_metadata = UNSET
        else:
            json_metadata = self.json_metadata

        long_descr: None | str | Unset
        if isinstance(self.long_descr, Unset):
            long_descr = UNSET
        else:
            long_descr = self.long_descr

        short_descr: None | str | Unset
        if isinstance(self.short_descr, Unset):
            short_descr = UNSET
        else:
            short_descr = self.short_descr

        start_dttm: None | str | Unset
        if isinstance(self.start_dttm, Unset):
            start_dttm = UNSET
        elif isinstance(self.start_dttm, datetime.datetime):
            start_dttm = self.start_dttm.isoformat()
        else:
            start_dttm = self.start_dttm

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "layer": layer,
            }
        )
        if end_dttm is not UNSET:
            field_dict["end_dttm"] = end_dttm
        if id is not UNSET:
            field_dict["id"] = id
        if json_metadata is not UNSET:
            field_dict["json_metadata"] = json_metadata
        if long_descr is not UNSET:
            field_dict["long_descr"] = long_descr
        if short_descr is not UNSET:
            field_dict["short_descr"] = short_descr
        if start_dttm is not UNSET:
            field_dict["start_dttm"] = start_dttm

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.annotation_rest_api_get_annotation_layer import AnnotationRestApiGetAnnotationLayer

        d = dict(src_dict)
        layer = AnnotationRestApiGetAnnotationLayer.from_dict(d.pop("layer"))

        def _parse_end_dttm(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                end_dttm_type_0 = isoparse(data)

                return end_dttm_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        end_dttm = _parse_end_dttm(d.pop("end_dttm", UNSET))

        id = d.pop("id", UNSET)

        def _parse_json_metadata(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        json_metadata = _parse_json_metadata(d.pop("json_metadata", UNSET))

        def _parse_long_descr(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        long_descr = _parse_long_descr(d.pop("long_descr", UNSET))

        def _parse_short_descr(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        short_descr = _parse_short_descr(d.pop("short_descr", UNSET))

        def _parse_start_dttm(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                start_dttm_type_0 = isoparse(data)

                return start_dttm_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        start_dttm = _parse_start_dttm(d.pop("start_dttm", UNSET))

        annotation_rest_api_get = cls(
            layer=layer,
            end_dttm=end_dttm,
            id=id,
            json_metadata=json_metadata,
            long_descr=long_descr,
            short_descr=short_descr,
            start_dttm=start_dttm,
        )

        annotation_rest_api_get.additional_properties = d
        return annotation_rest_api_get

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

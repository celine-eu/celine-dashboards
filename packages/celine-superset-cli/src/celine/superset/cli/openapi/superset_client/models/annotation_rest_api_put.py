from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnnotationRestApiPut")


@_attrs_define
class AnnotationRestApiPut:
    """
    Attributes:
        end_dttm (datetime.datetime | Unset): The annotation end date time
        json_metadata (None | str | Unset): JSON metadata
        long_descr (None | str | Unset): A long description
        short_descr (str | Unset): A short description
        start_dttm (datetime.datetime | Unset): The annotation start date time
    """

    end_dttm: datetime.datetime | Unset = UNSET
    json_metadata: None | str | Unset = UNSET
    long_descr: None | str | Unset = UNSET
    short_descr: str | Unset = UNSET
    start_dttm: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        end_dttm: str | Unset = UNSET
        if not isinstance(self.end_dttm, Unset):
            end_dttm = self.end_dttm.isoformat()

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

        short_descr = self.short_descr

        start_dttm: str | Unset = UNSET
        if not isinstance(self.start_dttm, Unset):
            start_dttm = self.start_dttm.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if end_dttm is not UNSET:
            field_dict["end_dttm"] = end_dttm
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
        d = dict(src_dict)
        _end_dttm = d.pop("end_dttm", UNSET)
        end_dttm: datetime.datetime | Unset
        if isinstance(_end_dttm, Unset):
            end_dttm = UNSET
        else:
            end_dttm = isoparse(_end_dttm)

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

        short_descr = d.pop("short_descr", UNSET)

        _start_dttm = d.pop("start_dttm", UNSET)
        start_dttm: datetime.datetime | Unset
        if isinstance(_start_dttm, Unset):
            start_dttm = UNSET
        else:
            start_dttm = isoparse(_start_dttm)

        annotation_rest_api_put = cls(
            end_dttm=end_dttm,
            json_metadata=json_metadata,
            long_descr=long_descr,
            short_descr=short_descr,
            start_dttm=start_dttm,
        )

        annotation_rest_api_put.additional_properties = d
        return annotation_rest_api_put

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

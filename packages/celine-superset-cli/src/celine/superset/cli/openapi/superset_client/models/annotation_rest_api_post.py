from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnnotationRestApiPost")


@_attrs_define
class AnnotationRestApiPost:
    """
    Attributes:
        end_dttm (datetime.datetime): The annotation end date time
        short_descr (str): A short description
        start_dttm (datetime.datetime): The annotation start date time
        json_metadata (None | str | Unset): JSON metadata
        long_descr (None | str | Unset): A long description
    """

    end_dttm: datetime.datetime
    short_descr: str
    start_dttm: datetime.datetime
    json_metadata: None | str | Unset = UNSET
    long_descr: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        end_dttm = self.end_dttm.isoformat()

        short_descr = self.short_descr

        start_dttm = self.start_dttm.isoformat()

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

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "end_dttm": end_dttm,
                "short_descr": short_descr,
                "start_dttm": start_dttm,
            }
        )
        if json_metadata is not UNSET:
            field_dict["json_metadata"] = json_metadata
        if long_descr is not UNSET:
            field_dict["long_descr"] = long_descr

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        end_dttm = isoparse(d.pop("end_dttm"))

        short_descr = d.pop("short_descr")

        start_dttm = isoparse(d.pop("start_dttm"))

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

        annotation_rest_api_post = cls(
            end_dttm=end_dttm,
            short_descr=short_descr,
            start_dttm=start_dttm,
            json_metadata=json_metadata,
            long_descr=long_descr,
        )

        annotation_rest_api_post.additional_properties = d
        return annotation_rest_api_post

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

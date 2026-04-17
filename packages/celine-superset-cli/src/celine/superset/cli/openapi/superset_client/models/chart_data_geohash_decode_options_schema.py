from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ChartDataGeohashDecodeOptionsSchema")


@_attrs_define
class ChartDataGeohashDecodeOptionsSchema:
    """
    Attributes:
        geohash (str): Name of source column containing geohash string
        latitude (str): Name of target column for decoded latitude
        longitude (str): Name of target column for decoded longitude
    """

    geohash: str
    latitude: str
    longitude: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        geohash = self.geohash

        latitude = self.latitude

        longitude = self.longitude

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "geohash": geohash,
                "latitude": latitude,
                "longitude": longitude,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        geohash = d.pop("geohash")

        latitude = d.pop("latitude")

        longitude = d.pop("longitude")

        chart_data_geohash_decode_options_schema = cls(
            geohash=geohash,
            latitude=latitude,
            longitude=longitude,
        )

        chart_data_geohash_decode_options_schema.additional_properties = d
        return chart_data_geohash_decode_options_schema

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

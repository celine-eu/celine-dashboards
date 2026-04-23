from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataGeodeticParseOptionsSchema")


@_attrs_define
class ChartDataGeodeticParseOptionsSchema:
    """
    Attributes:
        geodetic (str): Name of source column containing geodetic point strings
        latitude (str): Name of target column for decoded latitude
        longitude (str): Name of target column for decoded longitude
        altitude (str | Unset): Name of target column for decoded altitude. If omitted, altitude information in geodetic
            string is ignored.
    """

    geodetic: str
    latitude: str
    longitude: str
    altitude: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        geodetic = self.geodetic

        latitude = self.latitude

        longitude = self.longitude

        altitude = self.altitude

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "geodetic": geodetic,
                "latitude": latitude,
                "longitude": longitude,
            }
        )
        if altitude is not UNSET:
            field_dict["altitude"] = altitude

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        geodetic = d.pop("geodetic")

        latitude = d.pop("latitude")

        longitude = d.pop("longitude")

        altitude = d.pop("altitude", UNSET)

        chart_data_geodetic_parse_options_schema = cls(
            geodetic=geodetic,
            latitude=latitude,
            longitude=longitude,
            altitude=altitude,
        )

        chart_data_geodetic_parse_options_schema.additional_properties = d
        return chart_data_geodetic_parse_options_schema

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

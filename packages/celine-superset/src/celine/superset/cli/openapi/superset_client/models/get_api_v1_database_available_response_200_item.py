from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_database_available_response_200_item_engine_information import (
        GetApiV1DatabaseAvailableResponse200ItemEngineInformation,
    )
    from ..models.get_api_v1_database_available_response_200_item_parameters import (
        GetApiV1DatabaseAvailableResponse200ItemParameters,
    )


T = TypeVar("T", bound="GetApiV1DatabaseAvailableResponse200Item")


@_attrs_define
class GetApiV1DatabaseAvailableResponse200Item:
    """
    Attributes:
        available_drivers (list[str] | Unset): Installed drivers for the engine
        default_driver (str | Unset): Default driver for the engine
        engine (str | Unset): Name of the SQLAlchemy engine
        engine_information (GetApiV1DatabaseAvailableResponse200ItemEngineInformation | Unset): Dict with public
            properties form the DB Engine
        name (str | Unset): Name of the database
        parameters (GetApiV1DatabaseAvailableResponse200ItemParameters | Unset): JSON schema defining the needed
            parameters
        preferred (bool | Unset): Is the database preferred?
        sqlalchemy_uri_placeholder (str | Unset): Example placeholder for the SQLAlchemy URI
    """

    available_drivers: list[str] | Unset = UNSET
    default_driver: str | Unset = UNSET
    engine: str | Unset = UNSET
    engine_information: GetApiV1DatabaseAvailableResponse200ItemEngineInformation | Unset = UNSET
    name: str | Unset = UNSET
    parameters: GetApiV1DatabaseAvailableResponse200ItemParameters | Unset = UNSET
    preferred: bool | Unset = UNSET
    sqlalchemy_uri_placeholder: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        available_drivers: list[str] | Unset = UNSET
        if not isinstance(self.available_drivers, Unset):
            available_drivers = self.available_drivers

        default_driver = self.default_driver

        engine = self.engine

        engine_information: dict[str, Any] | Unset = UNSET
        if not isinstance(self.engine_information, Unset):
            engine_information = self.engine_information.to_dict()

        name = self.name

        parameters: dict[str, Any] | Unset = UNSET
        if not isinstance(self.parameters, Unset):
            parameters = self.parameters.to_dict()

        preferred = self.preferred

        sqlalchemy_uri_placeholder = self.sqlalchemy_uri_placeholder

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if available_drivers is not UNSET:
            field_dict["available_drivers"] = available_drivers
        if default_driver is not UNSET:
            field_dict["default_driver"] = default_driver
        if engine is not UNSET:
            field_dict["engine"] = engine
        if engine_information is not UNSET:
            field_dict["engine_information"] = engine_information
        if name is not UNSET:
            field_dict["name"] = name
        if parameters is not UNSET:
            field_dict["parameters"] = parameters
        if preferred is not UNSET:
            field_dict["preferred"] = preferred
        if sqlalchemy_uri_placeholder is not UNSET:
            field_dict["sqlalchemy_uri_placeholder"] = sqlalchemy_uri_placeholder

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_database_available_response_200_item_engine_information import (
            GetApiV1DatabaseAvailableResponse200ItemEngineInformation,
        )
        from ..models.get_api_v1_database_available_response_200_item_parameters import (
            GetApiV1DatabaseAvailableResponse200ItemParameters,
        )

        d = dict(src_dict)
        available_drivers = cast(list[str], d.pop("available_drivers", UNSET))

        default_driver = d.pop("default_driver", UNSET)

        engine = d.pop("engine", UNSET)

        _engine_information = d.pop("engine_information", UNSET)
        engine_information: GetApiV1DatabaseAvailableResponse200ItemEngineInformation | Unset
        if isinstance(_engine_information, Unset):
            engine_information = UNSET
        else:
            engine_information = GetApiV1DatabaseAvailableResponse200ItemEngineInformation.from_dict(
                _engine_information
            )

        name = d.pop("name", UNSET)

        _parameters = d.pop("parameters", UNSET)
        parameters: GetApiV1DatabaseAvailableResponse200ItemParameters | Unset
        if isinstance(_parameters, Unset):
            parameters = UNSET
        else:
            parameters = GetApiV1DatabaseAvailableResponse200ItemParameters.from_dict(_parameters)

        preferred = d.pop("preferred", UNSET)

        sqlalchemy_uri_placeholder = d.pop("sqlalchemy_uri_placeholder", UNSET)

        get_api_v1_database_available_response_200_item = cls(
            available_drivers=available_drivers,
            default_driver=default_driver,
            engine=engine,
            engine_information=engine_information,
            name=name,
            parameters=parameters,
            preferred=preferred,
            sqlalchemy_uri_placeholder=sqlalchemy_uri_placeholder,
        )

        get_api_v1_database_available_response_200_item.additional_properties = d
        return get_api_v1_database_available_response_200_item

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

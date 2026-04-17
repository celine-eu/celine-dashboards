from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatasetColumnsPut")


@_attrs_define
class DatasetColumnsPut:
    """
    Attributes:
        column_name (str):
        advanced_data_type (None | str | Unset):
        description (None | str | Unset):
        expression (None | str | Unset):
        extra (None | str | Unset):
        filterable (bool | Unset):
        groupby (bool | Unset):
        id (int | Unset):
        is_active (bool | None | Unset):
        is_dttm (bool | None | Unset):
        python_date_format (None | str | Unset):
        type_ (None | str | Unset):
        uuid (None | Unset | UUID):
        verbose_name (None | str | Unset):
    """

    column_name: str
    advanced_data_type: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    expression: None | str | Unset = UNSET
    extra: None | str | Unset = UNSET
    filterable: bool | Unset = UNSET
    groupby: bool | Unset = UNSET
    id: int | Unset = UNSET
    is_active: bool | None | Unset = UNSET
    is_dttm: bool | None | Unset = UNSET
    python_date_format: None | str | Unset = UNSET
    type_: None | str | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    verbose_name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        column_name = self.column_name

        advanced_data_type: None | str | Unset
        if isinstance(self.advanced_data_type, Unset):
            advanced_data_type = UNSET
        else:
            advanced_data_type = self.advanced_data_type

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        expression: None | str | Unset
        if isinstance(self.expression, Unset):
            expression = UNSET
        else:
            expression = self.expression

        extra: None | str | Unset
        if isinstance(self.extra, Unset):
            extra = UNSET
        else:
            extra = self.extra

        filterable = self.filterable

        groupby = self.groupby

        id = self.id

        is_active: bool | None | Unset
        if isinstance(self.is_active, Unset):
            is_active = UNSET
        else:
            is_active = self.is_active

        is_dttm: bool | None | Unset
        if isinstance(self.is_dttm, Unset):
            is_dttm = UNSET
        else:
            is_dttm = self.is_dttm

        python_date_format: None | str | Unset
        if isinstance(self.python_date_format, Unset):
            python_date_format = UNSET
        else:
            python_date_format = self.python_date_format

        type_: None | str | Unset
        if isinstance(self.type_, Unset):
            type_ = UNSET
        else:
            type_ = self.type_

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        verbose_name: None | str | Unset
        if isinstance(self.verbose_name, Unset):
            verbose_name = UNSET
        else:
            verbose_name = self.verbose_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "column_name": column_name,
            }
        )
        if advanced_data_type is not UNSET:
            field_dict["advanced_data_type"] = advanced_data_type
        if description is not UNSET:
            field_dict["description"] = description
        if expression is not UNSET:
            field_dict["expression"] = expression
        if extra is not UNSET:
            field_dict["extra"] = extra
        if filterable is not UNSET:
            field_dict["filterable"] = filterable
        if groupby is not UNSET:
            field_dict["groupby"] = groupby
        if id is not UNSET:
            field_dict["id"] = id
        if is_active is not UNSET:
            field_dict["is_active"] = is_active
        if is_dttm is not UNSET:
            field_dict["is_dttm"] = is_dttm
        if python_date_format is not UNSET:
            field_dict["python_date_format"] = python_date_format
        if type_ is not UNSET:
            field_dict["type"] = type_
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if verbose_name is not UNSET:
            field_dict["verbose_name"] = verbose_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        column_name = d.pop("column_name")

        def _parse_advanced_data_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        advanced_data_type = _parse_advanced_data_type(d.pop("advanced_data_type", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_expression(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expression = _parse_expression(d.pop("expression", UNSET))

        def _parse_extra(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extra = _parse_extra(d.pop("extra", UNSET))

        filterable = d.pop("filterable", UNSET)

        groupby = d.pop("groupby", UNSET)

        id = d.pop("id", UNSET)

        def _parse_is_active(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_active = _parse_is_active(d.pop("is_active", UNSET))

        def _parse_is_dttm(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        is_dttm = _parse_is_dttm(d.pop("is_dttm", UNSET))

        def _parse_python_date_format(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        python_date_format = _parse_python_date_format(d.pop("python_date_format", UNSET))

        def _parse_type_(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        type_ = _parse_type_(d.pop("type", UNSET))

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

        def _parse_verbose_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        verbose_name = _parse_verbose_name(d.pop("verbose_name", UNSET))

        dataset_columns_put = cls(
            column_name=column_name,
            advanced_data_type=advanced_data_type,
            description=description,
            expression=expression,
            extra=extra,
            filterable=filterable,
            groupby=groupby,
            id=id,
            is_active=is_active,
            is_dttm=is_dttm,
            python_date_format=python_date_format,
            type_=type_,
            uuid=uuid,
            verbose_name=verbose_name,
        )

        dataset_columns_put.additional_properties = d
        return dataset_columns_put

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.database_tables_response_extra import DatabaseTablesResponseExtra


T = TypeVar("T", bound="DatabaseTablesResponse")


@_attrs_define
class DatabaseTablesResponse:
    """
    Attributes:
        extra (DatabaseTablesResponseExtra | Unset): Extra data used to specify column metadata
        type_ (str | Unset): table or view
        value (str | Unset): The table or view name
    """

    extra: DatabaseTablesResponseExtra | Unset = UNSET
    type_: str | Unset = UNSET
    value: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        type_ = self.type_

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if extra is not UNSET:
            field_dict["extra"] = extra
        if type_ is not UNSET:
            field_dict["type"] = type_
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.database_tables_response_extra import DatabaseTablesResponseExtra

        d = dict(src_dict)
        _extra = d.pop("extra", UNSET)
        extra: DatabaseTablesResponseExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = DatabaseTablesResponseExtra.from_dict(_extra)

        type_ = d.pop("type", UNSET)

        value = d.pop("value", UNSET)

        database_tables_response = cls(
            extra=extra,
            type_=type_,
            value=value,
        )

        database_tables_response.additional_properties = d
        return database_tables_response

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

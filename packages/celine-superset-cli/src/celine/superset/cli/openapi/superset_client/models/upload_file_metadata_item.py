from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UploadFileMetadataItem")


@_attrs_define
class UploadFileMetadataItem:
    """
    Attributes:
        column_names (list[str] | Unset): A list of columns names in the sheet
        sheet_name (str | Unset): The name of the sheet
    """

    column_names: list[str] | Unset = UNSET
    sheet_name: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        column_names: list[str] | Unset = UNSET
        if not isinstance(self.column_names, Unset):
            column_names = self.column_names

        sheet_name = self.sheet_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if column_names is not UNSET:
            field_dict["column_names"] = column_names
        if sheet_name is not UNSET:
            field_dict["sheet_name"] = sheet_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        column_names = cast(list[str], d.pop("column_names", UNSET))

        sheet_name = d.pop("sheet_name", UNSET)

        upload_file_metadata_item = cls(
            column_names=column_names,
            sheet_name=sheet_name,
        )

        upload_file_metadata_item.additional_properties = d
        return upload_file_metadata_item

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

from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from .. import types
from ..models.upload_file_metadata_post_schema_type import (
    UploadFileMetadataPostSchemaType,
    check_upload_file_metadata_post_schema_type,
)
from ..types import UNSET, File, Unset

T = TypeVar("T", bound="UploadFileMetadataPostSchema")


@_attrs_define
class UploadFileMetadataPostSchema:
    """
    Attributes:
        file (File): The file to upload
        type_ (UploadFileMetadataPostSchemaType): File type to upload
        delimiter (str | Unset): The character used to separate values in the CSV file (e.g., a comma, semicolon, or
            tab).
        header_row (int | Unset): Row containing the headers to use as column names(0 is first line of data). Leave
            empty if there is no header row.
    """

    file: File
    type_: UploadFileMetadataPostSchemaType
    delimiter: str | Unset = UNSET
    header_row: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file = self.file.to_tuple()

        type_: str = self.type_

        delimiter = self.delimiter

        header_row = self.header_row

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file": file,
                "type": type_,
            }
        )
        if delimiter is not UNSET:
            field_dict["delimiter"] = delimiter
        if header_row is not UNSET:
            field_dict["header_row"] = header_row

        return field_dict

    def to_multipart(self) -> types.RequestFiles:
        files: types.RequestFiles = []

        files.append(("file", self.file.to_tuple()))

        files.append(("type", (None, str(self.type_).encode(), "text/plain")))

        if not isinstance(self.delimiter, Unset):
            files.append(("delimiter", (None, str(self.delimiter).encode(), "text/plain")))

        if not isinstance(self.header_row, Unset):
            files.append(("header_row", (None, str(self.header_row).encode(), "text/plain")))

        for prop_name, prop in self.additional_properties.items():
            files.append((prop_name, (None, str(prop).encode(), "text/plain")))

        return files

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file = File(payload=BytesIO(d.pop("file")))

        type_ = check_upload_file_metadata_post_schema_type(d.pop("type"))

        delimiter = d.pop("delimiter", UNSET)

        header_row = d.pop("header_row", UNSET)

        upload_file_metadata_post_schema = cls(
            file=file,
            type_=type_,
            delimiter=delimiter,
            header_row=header_row,
        )

        upload_file_metadata_post_schema.additional_properties = d
        return upload_file_metadata_post_schema

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

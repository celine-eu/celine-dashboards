from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from .. import types
from ..types import UNSET, File, FileTypes, Unset

T = TypeVar("T", bound="PostApiV1ThemeImportBody")


@_attrs_define
class PostApiV1ThemeImportBody:
    """
    Attributes:
        form_data (File | Unset):
        overwrite (str | Unset):
    """

    form_data: File | Unset = UNSET
    overwrite: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        form_data: FileTypes | Unset = UNSET
        if not isinstance(self.form_data, Unset):
            form_data = self.form_data.to_tuple()

        overwrite = self.overwrite

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if form_data is not UNSET:
            field_dict["formData"] = form_data
        if overwrite is not UNSET:
            field_dict["overwrite"] = overwrite

        return field_dict

    def to_multipart(self) -> types.RequestFiles:
        files: types.RequestFiles = []

        if not isinstance(self.form_data, Unset):
            files.append(("formData", self.form_data.to_tuple()))

        if not isinstance(self.overwrite, Unset):
            files.append(("overwrite", (None, str(self.overwrite).encode(), "text/plain")))

        for prop_name, prop in self.additional_properties.items():
            files.append((prop_name, (None, str(prop).encode(), "text/plain")))

        return files

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _form_data = d.pop("formData", UNSET)
        form_data: File | Unset
        if isinstance(_form_data, Unset):
            form_data = UNSET
        else:
            form_data = File(payload=BytesIO(_form_data))

        overwrite = d.pop("overwrite", UNSET)

        post_api_v1_theme_import_body = cls(
            form_data=form_data,
            overwrite=overwrite,
        )

        post_api_v1_theme_import_body.additional_properties = d
        return post_api_v1_theme_import_body

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

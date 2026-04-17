from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GetRelatedSchema")


@_attrs_define
class GetRelatedSchema:
    """
    Attributes:
        filter_ (str | Unset):
        include_ids (list[int] | Unset):
        page (int | Unset):
        page_size (int | Unset):
    """

    filter_: str | Unset = UNSET
    include_ids: list[int] | Unset = UNSET
    page: int | Unset = UNSET
    page_size: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        filter_ = self.filter_

        include_ids: list[int] | Unset = UNSET
        if not isinstance(self.include_ids, Unset):
            include_ids = self.include_ids

        page = self.page

        page_size = self.page_size

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if filter_ is not UNSET:
            field_dict["filter"] = filter_
        if include_ids is not UNSET:
            field_dict["include_ids"] = include_ids
        if page is not UNSET:
            field_dict["page"] = page
        if page_size is not UNSET:
            field_dict["page_size"] = page_size

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        filter_ = d.pop("filter", UNSET)

        include_ids = cast(list[int], d.pop("include_ids", UNSET))

        page = d.pop("page", UNSET)

        page_size = d.pop("page_size", UNSET)

        get_related_schema = cls(
            filter_=filter_,
            include_ids=include_ids,
            page=page,
            page_size=page_size,
        )

        get_related_schema.additional_properties = d
        return get_related_schema

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

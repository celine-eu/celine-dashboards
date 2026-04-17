from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_sqllab_results_response_410_errors_item import GetApiV1SqllabResultsResponse410ErrorsItem


T = TypeVar("T", bound="GetApiV1SqllabResultsResponse410")


@_attrs_define
class GetApiV1SqllabResultsResponse410:
    """
    Attributes:
        errors (list[GetApiV1SqllabResultsResponse410ErrorsItem] | Unset):
        message (str | Unset):
    """

    errors: list[GetApiV1SqllabResultsResponse410ErrorsItem] | Unset = UNSET
    message: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if errors is not UNSET:
            field_dict["errors"] = errors
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_sqllab_results_response_410_errors_item import (
            GetApiV1SqllabResultsResponse410ErrorsItem,
        )

        d = dict(src_dict)
        _errors = d.pop("errors", UNSET)
        errors: list[GetApiV1SqllabResultsResponse410ErrorsItem] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = GetApiV1SqllabResultsResponse410ErrorsItem.from_dict(errors_item_data)

                errors.append(errors_item)

        message = d.pop("message", UNSET)

        get_api_v1_sqllab_results_response_410 = cls(
            errors=errors,
            message=message,
        )

        get_api_v1_sqllab_results_response_410.additional_properties = d
        return get_api_v1_sqllab_results_response_410

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

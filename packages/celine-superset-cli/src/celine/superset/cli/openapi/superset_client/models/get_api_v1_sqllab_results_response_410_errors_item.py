from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.get_api_v1_sqllab_results_response_410_errors_item_error_type import (
    GetApiV1SqllabResultsResponse410ErrorsItemErrorType,
    check_get_api_v1_sqllab_results_response_410_errors_item_error_type,
)
from ..models.get_api_v1_sqllab_results_response_410_errors_item_level import (
    GetApiV1SqllabResultsResponse410ErrorsItemLevel,
    check_get_api_v1_sqllab_results_response_410_errors_item_level,
)
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_sqllab_results_response_410_errors_item_extra import (
        GetApiV1SqllabResultsResponse410ErrorsItemExtra,
    )


T = TypeVar("T", bound="GetApiV1SqllabResultsResponse410ErrorsItem")


@_attrs_define
class GetApiV1SqllabResultsResponse410ErrorsItem:
    """
    Attributes:
        error_type (GetApiV1SqllabResultsResponse410ErrorsItemErrorType | Unset):
        extra (GetApiV1SqllabResultsResponse410ErrorsItemExtra | Unset):
        level (GetApiV1SqllabResultsResponse410ErrorsItemLevel | Unset):
        message (str | Unset):
    """

    error_type: GetApiV1SqllabResultsResponse410ErrorsItemErrorType | Unset = UNSET
    extra: GetApiV1SqllabResultsResponse410ErrorsItemExtra | Unset = UNSET
    level: GetApiV1SqllabResultsResponse410ErrorsItemLevel | Unset = UNSET
    message: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        error_type: str | Unset = UNSET
        if not isinstance(self.error_type, Unset):
            error_type = self.error_type

        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        level: str | Unset = UNSET
        if not isinstance(self.level, Unset):
            level = self.level

        message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if error_type is not UNSET:
            field_dict["error_type"] = error_type
        if extra is not UNSET:
            field_dict["extra"] = extra
        if level is not UNSET:
            field_dict["level"] = level
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_sqllab_results_response_410_errors_item_extra import (
            GetApiV1SqllabResultsResponse410ErrorsItemExtra,
        )

        d = dict(src_dict)
        _error_type = d.pop("error_type", UNSET)
        error_type: GetApiV1SqllabResultsResponse410ErrorsItemErrorType | Unset
        if isinstance(_error_type, Unset):
            error_type = UNSET
        else:
            error_type = check_get_api_v1_sqllab_results_response_410_errors_item_error_type(_error_type)

        _extra = d.pop("extra", UNSET)
        extra: GetApiV1SqllabResultsResponse410ErrorsItemExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = GetApiV1SqllabResultsResponse410ErrorsItemExtra.from_dict(_extra)

        _level = d.pop("level", UNSET)
        level: GetApiV1SqllabResultsResponse410ErrorsItemLevel | Unset
        if isinstance(_level, Unset):
            level = UNSET
        else:
            level = check_get_api_v1_sqllab_results_response_410_errors_item_level(_level)

        message = d.pop("message", UNSET)

        get_api_v1_sqllab_results_response_410_errors_item = cls(
            error_type=error_type,
            extra=extra,
            level=level,
            message=message,
        )

        get_api_v1_sqllab_results_response_410_errors_item.additional_properties = d
        return get_api_v1_sqllab_results_response_410_errors_item

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_async_event_response_200_result_item_errors_item import (
        GetApiV1AsyncEventResponse200ResultItemErrorsItem,
    )


T = TypeVar("T", bound="GetApiV1AsyncEventResponse200ResultItem")


@_attrs_define
class GetApiV1AsyncEventResponse200ResultItem:
    """
    Attributes:
        channel_id (str | Unset):
        errors (list[GetApiV1AsyncEventResponse200ResultItemErrorsItem] | Unset):
        id (str | Unset):
        job_id (str | Unset):
        result_url (str | Unset):
        status (str | Unset):
        user_id (int | Unset):
    """

    channel_id: str | Unset = UNSET
    errors: list[GetApiV1AsyncEventResponse200ResultItemErrorsItem] | Unset = UNSET
    id: str | Unset = UNSET
    job_id: str | Unset = UNSET
    result_url: str | Unset = UNSET
    status: str | Unset = UNSET
    user_id: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        channel_id = self.channel_id

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        id = self.id

        job_id = self.job_id

        result_url = self.result_url

        status = self.status

        user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if channel_id is not UNSET:
            field_dict["channel_id"] = channel_id
        if errors is not UNSET:
            field_dict["errors"] = errors
        if id is not UNSET:
            field_dict["id"] = id
        if job_id is not UNSET:
            field_dict["job_id"] = job_id
        if result_url is not UNSET:
            field_dict["result_url"] = result_url
        if status is not UNSET:
            field_dict["status"] = status
        if user_id is not UNSET:
            field_dict["user_id"] = user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_async_event_response_200_result_item_errors_item import (
            GetApiV1AsyncEventResponse200ResultItemErrorsItem,
        )

        d = dict(src_dict)
        channel_id = d.pop("channel_id", UNSET)

        _errors = d.pop("errors", UNSET)
        errors: list[GetApiV1AsyncEventResponse200ResultItemErrorsItem] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = GetApiV1AsyncEventResponse200ResultItemErrorsItem.from_dict(errors_item_data)

                errors.append(errors_item)

        id = d.pop("id", UNSET)

        job_id = d.pop("job_id", UNSET)

        result_url = d.pop("result_url", UNSET)

        status = d.pop("status", UNSET)

        user_id = d.pop("user_id", UNSET)

        get_api_v1_async_event_response_200_result_item = cls(
            channel_id=channel_id,
            errors=errors,
            id=id,
            job_id=job_id,
            result_url=result_url,
            status=status,
            user_id=user_id,
        )

        get_api_v1_async_event_response_200_result_item.additional_properties = d
        return get_api_v1_async_event_response_200_result_item

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

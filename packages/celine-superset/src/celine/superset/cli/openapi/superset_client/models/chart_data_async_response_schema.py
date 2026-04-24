from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChartDataAsyncResponseSchema")


@_attrs_define
class ChartDataAsyncResponseSchema:
    """
    Attributes:
        channel_id (str | Unset): Unique session async channel ID
        job_id (str | Unset): Unique async job ID
        result_url (str | Unset): Unique result URL for fetching async query data
        status (str | Unset): Status value for async job
        user_id (None | str | Unset): Requesting user ID
    """

    channel_id: str | Unset = UNSET
    job_id: str | Unset = UNSET
    result_url: str | Unset = UNSET
    status: str | Unset = UNSET
    user_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        channel_id = self.channel_id

        job_id = self.job_id

        result_url = self.result_url

        status = self.status

        user_id: None | str | Unset
        if isinstance(self.user_id, Unset):
            user_id = UNSET
        else:
            user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if channel_id is not UNSET:
            field_dict["channel_id"] = channel_id
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
        d = dict(src_dict)
        channel_id = d.pop("channel_id", UNSET)

        job_id = d.pop("job_id", UNSET)

        result_url = d.pop("result_url", UNSET)

        status = d.pop("status", UNSET)

        def _parse_user_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        user_id = _parse_user_id(d.pop("user_id", UNSET))

        chart_data_async_response_schema = cls(
            channel_id=channel_id,
            job_id=job_id,
            result_url=result_url,
            status=status,
            user_id=user_id,
        )

        chart_data_async_response_schema.additional_properties = d
        return chart_data_async_response_schema

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

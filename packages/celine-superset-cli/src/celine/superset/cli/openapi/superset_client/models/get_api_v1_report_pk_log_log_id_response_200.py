from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.report_execution_log_rest_api_get import ReportExecutionLogRestApiGet


T = TypeVar("T", bound="GetApiV1ReportPkLogLogIdResponse200")


@_attrs_define
class GetApiV1ReportPkLogLogIdResponse200:
    """
    Attributes:
        id (str | Unset): The log id
        result (ReportExecutionLogRestApiGet | Unset):
    """

    id: str | Unset = UNSET
    result: ReportExecutionLogRestApiGet | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        result: dict[str, Any] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = self.result.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.report_execution_log_rest_api_get import ReportExecutionLogRestApiGet

        d = dict(src_dict)
        id = d.pop("id", UNSET)

        _result = d.pop("result", UNSET)
        result: ReportExecutionLogRestApiGet | Unset
        if isinstance(_result, Unset):
            result = UNSET
        else:
            result = ReportExecutionLogRestApiGet.from_dict(_result)

        get_api_v1_report_pk_log_log_id_response_200 = cls(
            id=id,
            result=result,
        )

        get_api_v1_report_pk_log_log_id_response_200.additional_properties = d
        return get_api_v1_report_pk_log_log_id_response_200

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

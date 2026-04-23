from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.database_tables_response import DatabaseTablesResponse


T = TypeVar("T", bound="GetApiV1DatabasePkTablesResponse200")


@_attrs_define
class GetApiV1DatabasePkTablesResponse200:
    """
    Attributes:
        count (int | Unset):
        result (list[DatabaseTablesResponse] | Unset): A List of tables for given database
    """

    count: int | Unset = UNSET
    result: list[DatabaseTablesResponse] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        count = self.count

        result: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = []
            for result_item_data in self.result:
                result_item = result_item_data.to_dict()
                result.append(result_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if count is not UNSET:
            field_dict["count"] = count
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.database_tables_response import DatabaseTablesResponse

        d = dict(src_dict)
        count = d.pop("count", UNSET)

        _result = d.pop("result", UNSET)
        result: list[DatabaseTablesResponse] | Unset = UNSET
        if _result is not UNSET:
            result = []
            for result_item_data in _result:
                result_item = DatabaseTablesResponse.from_dict(result_item_data)

                result.append(result_item)

        get_api_v1_database_pk_tables_response_200 = cls(
            count=count,
            result=result,
        )

        get_api_v1_database_pk_tables_response_200.additional_properties = d
        return get_api_v1_database_pk_tables_response_200

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

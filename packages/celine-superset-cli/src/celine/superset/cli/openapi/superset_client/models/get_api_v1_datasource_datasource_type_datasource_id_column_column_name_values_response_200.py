from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_200_result_item_type_4 import (
        GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4,
    )


T = TypeVar("T", bound="GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200")


@_attrs_define
class GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200:
    """
    Attributes:
        result (list[bool | float |
            GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4 | int | str] |
            Unset):
    """

    result: (
        list[
            bool
            | float
            | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4
            | int
            | str
        ]
        | Unset
    ) = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_200_result_item_type_4 import (
            GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4,
        )

        result: list[bool | dict[str, Any] | float | int | str] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = []
            for result_item_data in self.result:
                result_item: bool | dict[str, Any] | float | int | str
                if isinstance(
                    result_item_data,
                    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4,
                ):
                    result_item = result_item_data.to_dict()
                else:
                    result_item = result_item_data
                result.append(result_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_200_result_item_type_4 import (
            GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4,
        )

        d = dict(src_dict)
        _result = d.pop("result", UNSET)
        result: (
            list[
                bool
                | float
                | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4
                | int
                | str
            ]
            | Unset
        ) = UNSET
        if _result is not UNSET:
            result = []
            for result_item_data in _result:

                def _parse_result_item(
                    data: object,
                ) -> (
                    bool
                    | float
                    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4
                    | int
                    | str
                ):
                    try:
                        if not isinstance(data, dict):
                            raise TypeError()
                        result_item_type_4 = GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4.from_dict(
                            data
                        )

                        return result_item_type_4
                    except (TypeError, ValueError, AttributeError, KeyError):
                        pass
                    return cast(
                        bool
                        | float
                        | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200ResultItemType4
                        | int
                        | str,
                        data,
                    )

                result_item = _parse_result_item(result_item_data)

                result.append(result_item)

        get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_200 = cls(
            result=result,
        )

        get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_200.additional_properties = d
        return get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_200

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

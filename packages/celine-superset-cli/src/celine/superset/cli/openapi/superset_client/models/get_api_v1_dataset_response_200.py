from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset_rest_api_get_list import DatasetRestApiGetList
    from ..models.get_api_v1_dataset_response_200_description_columns import (
        GetApiV1DatasetResponse200DescriptionColumns,
    )
    from ..models.get_api_v1_dataset_response_200_label_columns import GetApiV1DatasetResponse200LabelColumns


T = TypeVar("T", bound="GetApiV1DatasetResponse200")


@_attrs_define
class GetApiV1DatasetResponse200:
    """
    Attributes:
        count (float | Unset): The total record count on the backend
        description_columns (GetApiV1DatasetResponse200DescriptionColumns | Unset):
        ids (list[str] | Unset): A list of item ids, useful when you don't know the column id
        label_columns (GetApiV1DatasetResponse200LabelColumns | Unset):
        list_columns (list[str] | Unset): A list of columns
        list_title (str | Unset): A title to render. Will be translated by babel Example: List Items.
        order_columns (list[str] | Unset): A list of allowed columns to sort
        result (list[DatasetRestApiGetList] | Unset): The result from the get list query
    """

    count: float | Unset = UNSET
    description_columns: GetApiV1DatasetResponse200DescriptionColumns | Unset = UNSET
    ids: list[str] | Unset = UNSET
    label_columns: GetApiV1DatasetResponse200LabelColumns | Unset = UNSET
    list_columns: list[str] | Unset = UNSET
    list_title: str | Unset = UNSET
    order_columns: list[str] | Unset = UNSET
    result: list[DatasetRestApiGetList] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        count = self.count

        description_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.description_columns, Unset):
            description_columns = self.description_columns.to_dict()

        ids: list[str] | Unset = UNSET
        if not isinstance(self.ids, Unset):
            ids = self.ids

        label_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.label_columns, Unset):
            label_columns = self.label_columns.to_dict()

        list_columns: list[str] | Unset = UNSET
        if not isinstance(self.list_columns, Unset):
            list_columns = self.list_columns

        list_title = self.list_title

        order_columns: list[str] | Unset = UNSET
        if not isinstance(self.order_columns, Unset):
            order_columns = self.order_columns

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
        if description_columns is not UNSET:
            field_dict["description_columns"] = description_columns
        if ids is not UNSET:
            field_dict["ids"] = ids
        if label_columns is not UNSET:
            field_dict["label_columns"] = label_columns
        if list_columns is not UNSET:
            field_dict["list_columns"] = list_columns
        if list_title is not UNSET:
            field_dict["list_title"] = list_title
        if order_columns is not UNSET:
            field_dict["order_columns"] = order_columns
        if result is not UNSET:
            field_dict["result"] = result

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset_rest_api_get_list import DatasetRestApiGetList
        from ..models.get_api_v1_dataset_response_200_description_columns import (
            GetApiV1DatasetResponse200DescriptionColumns,
        )
        from ..models.get_api_v1_dataset_response_200_label_columns import GetApiV1DatasetResponse200LabelColumns

        d = dict(src_dict)
        count = d.pop("count", UNSET)

        _description_columns = d.pop("description_columns", UNSET)
        description_columns: GetApiV1DatasetResponse200DescriptionColumns | Unset
        if isinstance(_description_columns, Unset):
            description_columns = UNSET
        else:
            description_columns = GetApiV1DatasetResponse200DescriptionColumns.from_dict(_description_columns)

        ids = cast(list[str], d.pop("ids", UNSET))

        _label_columns = d.pop("label_columns", UNSET)
        label_columns: GetApiV1DatasetResponse200LabelColumns | Unset
        if isinstance(_label_columns, Unset):
            label_columns = UNSET
        else:
            label_columns = GetApiV1DatasetResponse200LabelColumns.from_dict(_label_columns)

        list_columns = cast(list[str], d.pop("list_columns", UNSET))

        list_title = d.pop("list_title", UNSET)

        order_columns = cast(list[str], d.pop("order_columns", UNSET))

        _result = d.pop("result", UNSET)
        result: list[DatasetRestApiGetList] | Unset = UNSET
        if _result is not UNSET:
            result = []
            for result_item_data in _result:
                result_item = DatasetRestApiGetList.from_dict(result_item_data)

                result.append(result_item)

        get_api_v1_dataset_response_200 = cls(
            count=count,
            description_columns=description_columns,
            ids=ids,
            label_columns=label_columns,
            list_columns=list_columns,
            list_title=list_title,
            order_columns=order_columns,
            result=result,
        )

        get_api_v1_dataset_response_200.additional_properties = d
        return get_api_v1_dataset_response_200

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

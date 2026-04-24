from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.chart_data_select_options_schema_rename_item import ChartDataSelectOptionsSchemaRenameItem


T = TypeVar("T", bound="ChartDataSelectOptionsSchema")


@_attrs_define
class ChartDataSelectOptionsSchema:
    """
    Attributes:
        columns (list[str] | Unset): Columns which to select from the input data, in the desired order. If columns are
            renamed, the original column name should be referenced here. Example: ['country', 'gender', 'age'].
        exclude (list[str] | Unset): Columns to exclude from selection. Example: ['my_temp_column'].
        rename (list[ChartDataSelectOptionsSchemaRenameItem] | Unset): columns which to rename, mapping source column to
            target column. For instance, `{'y': 'y2'}` will rename the column `y` to `y2`. Example: [{'age':
            'average_age'}].
    """

    columns: list[str] | Unset = UNSET
    exclude: list[str] | Unset = UNSET
    rename: list[ChartDataSelectOptionsSchemaRenameItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        columns: list[str] | Unset = UNSET
        if not isinstance(self.columns, Unset):
            columns = self.columns

        exclude: list[str] | Unset = UNSET
        if not isinstance(self.exclude, Unset):
            exclude = self.exclude

        rename: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.rename, Unset):
            rename = []
            for rename_item_data in self.rename:
                rename_item = rename_item_data.to_dict()
                rename.append(rename_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if columns is not UNSET:
            field_dict["columns"] = columns
        if exclude is not UNSET:
            field_dict["exclude"] = exclude
        if rename is not UNSET:
            field_dict["rename"] = rename

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.chart_data_select_options_schema_rename_item import ChartDataSelectOptionsSchemaRenameItem

        d = dict(src_dict)
        columns = cast(list[str], d.pop("columns", UNSET))

        exclude = cast(list[str], d.pop("exclude", UNSET))

        _rename = d.pop("rename", UNSET)
        rename: list[ChartDataSelectOptionsSchemaRenameItem] | Unset = UNSET
        if _rename is not UNSET:
            rename = []
            for rename_item_data in _rename:
                rename_item = ChartDataSelectOptionsSchemaRenameItem.from_dict(rename_item_data)

                rename.append(rename_item)

        chart_data_select_options_schema = cls(
            columns=columns,
            exclude=exclude,
            rename=rename,
        )

        chart_data_select_options_schema.additional_properties = d
        return chart_data_select_options_schema

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

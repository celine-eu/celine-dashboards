from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dataset import Dataset
    from ..models.explore_context_schema_form_data import ExploreContextSchemaFormData
    from ..models.slice_ import Slice


T = TypeVar("T", bound="ExploreContextSchema")


@_attrs_define
class ExploreContextSchema:
    """
    Attributes:
        dataset (Dataset | Unset):
        form_data (ExploreContextSchemaFormData | Unset): Form data from the Explore controls used to form the chart's
            data query.
        message (str | Unset): Any message related to the processed request.
        slice_ (Slice | Unset):
    """

    dataset: Dataset | Unset = UNSET
    form_data: ExploreContextSchemaFormData | Unset = UNSET
    message: str | Unset = UNSET
    slice_: Slice | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dataset: dict[str, Any] | Unset = UNSET
        if not isinstance(self.dataset, Unset):
            dataset = self.dataset.to_dict()

        form_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.form_data, Unset):
            form_data = self.form_data.to_dict()

        message = self.message

        slice_: dict[str, Any] | Unset = UNSET
        if not isinstance(self.slice_, Unset):
            slice_ = self.slice_.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if dataset is not UNSET:
            field_dict["dataset"] = dataset
        if form_data is not UNSET:
            field_dict["form_data"] = form_data
        if message is not UNSET:
            field_dict["message"] = message
        if slice_ is not UNSET:
            field_dict["slice"] = slice_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dataset import Dataset
        from ..models.explore_context_schema_form_data import ExploreContextSchemaFormData
        from ..models.slice_ import Slice

        d = dict(src_dict)
        _dataset = d.pop("dataset", UNSET)
        dataset: Dataset | Unset
        if isinstance(_dataset, Unset):
            dataset = UNSET
        else:
            dataset = Dataset.from_dict(_dataset)

        _form_data = d.pop("form_data", UNSET)
        form_data: ExploreContextSchemaFormData | Unset
        if isinstance(_form_data, Unset):
            form_data = UNSET
        else:
            form_data = ExploreContextSchemaFormData.from_dict(_form_data)

        message = d.pop("message", UNSET)

        _slice_ = d.pop("slice", UNSET)
        slice_: Slice | Unset
        if isinstance(_slice_, Unset):
            slice_ = UNSET
        else:
            slice_ = Slice.from_dict(_slice_)

        explore_context_schema = cls(
            dataset=dataset,
            form_data=form_data,
            message=message,
            slice_=slice_,
        )

        explore_context_schema.additional_properties = d
        return explore_context_schema

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

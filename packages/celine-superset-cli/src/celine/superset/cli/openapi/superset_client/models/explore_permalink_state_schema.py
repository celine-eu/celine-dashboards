from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.explore_permalink_state_schema_form_data import ExplorePermalinkStateSchemaFormData


T = TypeVar("T", bound="ExplorePermalinkStateSchema")


@_attrs_define
class ExplorePermalinkStateSchema:
    """
    Attributes:
        form_data (ExplorePermalinkStateSchemaFormData): Chart form data
        url_params (list[Any] | None | Unset): URL Parameters
    """

    form_data: ExplorePermalinkStateSchemaFormData
    url_params: list[Any] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        form_data = self.form_data.to_dict()

        url_params: list[Any] | None | Unset
        if isinstance(self.url_params, Unset):
            url_params = UNSET
        elif isinstance(self.url_params, list):
            url_params = self.url_params

        else:
            url_params = self.url_params

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "formData": form_data,
            }
        )
        if url_params is not UNSET:
            field_dict["urlParams"] = url_params

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.explore_permalink_state_schema_form_data import ExplorePermalinkStateSchemaFormData

        d = dict(src_dict)
        form_data = ExplorePermalinkStateSchemaFormData.from_dict(d.pop("formData"))

        def _parse_url_params(data: object) -> list[Any] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                url_params_type_0 = cast(list[Any], data)

                return url_params_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Any] | None | Unset, data)

        url_params = _parse_url_params(d.pop("urlParams", UNSET))

        explore_permalink_state_schema = cls(
            form_data=form_data,
            url_params=url_params,
        )

        explore_permalink_state_schema.additional_properties = d
        return explore_permalink_state_schema

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

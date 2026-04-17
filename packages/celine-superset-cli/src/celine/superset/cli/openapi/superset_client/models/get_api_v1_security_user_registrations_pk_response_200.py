from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.get_api_v1_security_user_registrations_pk_response_200_description_columns import (
        GetApiV1SecurityUserRegistrationsPkResponse200DescriptionColumns,
    )
    from ..models.get_api_v1_security_user_registrations_pk_response_200_label_columns import (
        GetApiV1SecurityUserRegistrationsPkResponse200LabelColumns,
    )
    from ..models.user_registrations_rest_api_get import UserRegistrationsRestAPIGet


T = TypeVar("T", bound="GetApiV1SecurityUserRegistrationsPkResponse200")


@_attrs_define
class GetApiV1SecurityUserRegistrationsPkResponse200:
    """
    Attributes:
        description_columns (GetApiV1SecurityUserRegistrationsPkResponse200DescriptionColumns | Unset):
        id (str | Unset): The item id
        label_columns (GetApiV1SecurityUserRegistrationsPkResponse200LabelColumns | Unset):
        result (UserRegistrationsRestAPIGet | Unset):
        show_columns (list[str] | Unset): A list of columns
        show_title (str | Unset): A title to render. Will be translated by babel Example: Show Item Details.
    """

    description_columns: GetApiV1SecurityUserRegistrationsPkResponse200DescriptionColumns | Unset = UNSET
    id: str | Unset = UNSET
    label_columns: GetApiV1SecurityUserRegistrationsPkResponse200LabelColumns | Unset = UNSET
    result: UserRegistrationsRestAPIGet | Unset = UNSET
    show_columns: list[str] | Unset = UNSET
    show_title: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.description_columns, Unset):
            description_columns = self.description_columns.to_dict()

        id = self.id

        label_columns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.label_columns, Unset):
            label_columns = self.label_columns.to_dict()

        result: dict[str, Any] | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = self.result.to_dict()

        show_columns: list[str] | Unset = UNSET
        if not isinstance(self.show_columns, Unset):
            show_columns = self.show_columns

        show_title = self.show_title

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description_columns is not UNSET:
            field_dict["description_columns"] = description_columns
        if id is not UNSET:
            field_dict["id"] = id
        if label_columns is not UNSET:
            field_dict["label_columns"] = label_columns
        if result is not UNSET:
            field_dict["result"] = result
        if show_columns is not UNSET:
            field_dict["show_columns"] = show_columns
        if show_title is not UNSET:
            field_dict["show_title"] = show_title

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.get_api_v1_security_user_registrations_pk_response_200_description_columns import (
            GetApiV1SecurityUserRegistrationsPkResponse200DescriptionColumns,
        )
        from ..models.get_api_v1_security_user_registrations_pk_response_200_label_columns import (
            GetApiV1SecurityUserRegistrationsPkResponse200LabelColumns,
        )
        from ..models.user_registrations_rest_api_get import UserRegistrationsRestAPIGet

        d = dict(src_dict)
        _description_columns = d.pop("description_columns", UNSET)
        description_columns: GetApiV1SecurityUserRegistrationsPkResponse200DescriptionColumns | Unset
        if isinstance(_description_columns, Unset):
            description_columns = UNSET
        else:
            description_columns = GetApiV1SecurityUserRegistrationsPkResponse200DescriptionColumns.from_dict(
                _description_columns
            )

        id = d.pop("id", UNSET)

        _label_columns = d.pop("label_columns", UNSET)
        label_columns: GetApiV1SecurityUserRegistrationsPkResponse200LabelColumns | Unset
        if isinstance(_label_columns, Unset):
            label_columns = UNSET
        else:
            label_columns = GetApiV1SecurityUserRegistrationsPkResponse200LabelColumns.from_dict(_label_columns)

        _result = d.pop("result", UNSET)
        result: UserRegistrationsRestAPIGet | Unset
        if isinstance(_result, Unset):
            result = UNSET
        else:
            result = UserRegistrationsRestAPIGet.from_dict(_result)

        show_columns = cast(list[str], d.pop("show_columns", UNSET))

        show_title = d.pop("show_title", UNSET)

        get_api_v1_security_user_registrations_pk_response_200 = cls(
            description_columns=description_columns,
            id=id,
            label_columns=label_columns,
            result=result,
            show_columns=show_columns,
            show_title=show_title,
        )

        get_api_v1_security_user_registrations_pk_response_200.additional_properties = d
        return get_api_v1_security_user_registrations_pk_response_200

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

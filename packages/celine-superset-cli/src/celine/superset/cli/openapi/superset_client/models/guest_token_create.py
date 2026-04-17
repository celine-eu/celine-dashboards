from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.resource import Resource
    from ..models.rls_rule import RlsRule
    from ..models.user_3 import User3


T = TypeVar("T", bound="GuestTokenCreate")


@_attrs_define
class GuestTokenCreate:
    """
    Attributes:
        resources (list[Resource]):
        rls (list[RlsRule]):
        user (User3 | Unset):
    """

    resources: list[Resource]
    rls: list[RlsRule]
    user: User3 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resources = []
        for resources_item_data in self.resources:
            resources_item = resources_item_data.to_dict()
            resources.append(resources_item)

        rls = []
        for rls_item_data in self.rls:
            rls_item = rls_item_data.to_dict()
            rls.append(rls_item)

        user: dict[str, Any] | Unset = UNSET
        if not isinstance(self.user, Unset):
            user = self.user.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resources": resources,
                "rls": rls,
            }
        )
        if user is not UNSET:
            field_dict["user"] = user

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.resource import Resource
        from ..models.rls_rule import RlsRule
        from ..models.user_3 import User3

        d = dict(src_dict)
        resources = []
        _resources = d.pop("resources")
        for resources_item_data in _resources:
            resources_item = Resource.from_dict(resources_item_data)

            resources.append(resources_item)

        rls = []
        _rls = d.pop("rls")
        for rls_item_data in _rls:
            rls_item = RlsRule.from_dict(rls_item_data)

            rls.append(rls_item)

        _user = d.pop("user", UNSET)
        user: User3 | Unset
        if isinstance(_user, Unset):
            user = UNSET
        else:
            user = User3.from_dict(_user)

        guest_token_create = cls(
            resources=resources,
            rls=rls,
            user=user,
        )

        guest_token_create.additional_properties = d
        return guest_token_create

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

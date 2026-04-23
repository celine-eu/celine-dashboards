from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.user_2 import User2


T = TypeVar("T", bound="EmbeddedDashboardResponseSchema")


@_attrs_define
class EmbeddedDashboardResponseSchema:
    """
    Attributes:
        allowed_domains (list[str] | Unset):
        changed_by (User2 | Unset):
        changed_on (datetime.datetime | Unset):
        dashboard_id (str | Unset):
        uuid (str | Unset):
    """

    allowed_domains: list[str] | Unset = UNSET
    changed_by: User2 | Unset = UNSET
    changed_on: datetime.datetime | Unset = UNSET
    dashboard_id: str | Unset = UNSET
    uuid: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        allowed_domains: list[str] | Unset = UNSET
        if not isinstance(self.allowed_domains, Unset):
            allowed_domains = self.allowed_domains

        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on: str | Unset = UNSET
        if not isinstance(self.changed_on, Unset):
            changed_on = self.changed_on.isoformat()

        dashboard_id = self.dashboard_id

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if allowed_domains is not UNSET:
            field_dict["allowed_domains"] = allowed_domains
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if dashboard_id is not UNSET:
            field_dict["dashboard_id"] = dashboard_id
        if uuid is not UNSET:
            field_dict["uuid"] = uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.user_2 import User2

        d = dict(src_dict)
        allowed_domains = cast(list[str], d.pop("allowed_domains", UNSET))

        _changed_by = d.pop("changed_by", UNSET)
        changed_by: User2 | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = User2.from_dict(_changed_by)

        _changed_on = d.pop("changed_on", UNSET)
        changed_on: datetime.datetime | Unset
        if isinstance(_changed_on, Unset):
            changed_on = UNSET
        else:
            changed_on = isoparse(_changed_on)

        dashboard_id = d.pop("dashboard_id", UNSET)

        uuid = d.pop("uuid", UNSET)

        embedded_dashboard_response_schema = cls(
            allowed_domains=allowed_domains,
            changed_by=changed_by,
            changed_on=changed_on,
            dashboard_id=dashboard_id,
            uuid=uuid,
        )

        embedded_dashboard_response_schema.additional_properties = d
        return embedded_dashboard_response_schema

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

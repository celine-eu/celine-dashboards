from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.tab import Tab
    from ..models.tabs_payload_schema_all_tabs import TabsPayloadSchemaAllTabs


T = TypeVar("T", bound="TabsPayloadSchema")


@_attrs_define
class TabsPayloadSchema:
    """
    Attributes:
        all_tabs (TabsPayloadSchemaAllTabs | Unset):
        tab_tree (list[Tab] | Unset):
    """

    all_tabs: TabsPayloadSchemaAllTabs | Unset = UNSET
    tab_tree: list[Tab] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        all_tabs: dict[str, Any] | Unset = UNSET
        if not isinstance(self.all_tabs, Unset):
            all_tabs = self.all_tabs.to_dict()

        tab_tree: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.tab_tree, Unset):
            tab_tree = []
            for tab_tree_item_data in self.tab_tree:
                tab_tree_item = tab_tree_item_data.to_dict()
                tab_tree.append(tab_tree_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if all_tabs is not UNSET:
            field_dict["all_tabs"] = all_tabs
        if tab_tree is not UNSET:
            field_dict["tab_tree"] = tab_tree

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.tab import Tab
        from ..models.tabs_payload_schema_all_tabs import TabsPayloadSchemaAllTabs

        d = dict(src_dict)
        _all_tabs = d.pop("all_tabs", UNSET)
        all_tabs: TabsPayloadSchemaAllTabs | Unset
        if isinstance(_all_tabs, Unset):
            all_tabs = UNSET
        else:
            all_tabs = TabsPayloadSchemaAllTabs.from_dict(_all_tabs)

        _tab_tree = d.pop("tab_tree", UNSET)
        tab_tree: list[Tab] | Unset = UNSET
        if _tab_tree is not UNSET:
            tab_tree = []
            for tab_tree_item_data in _tab_tree:
                tab_tree_item = Tab.from_dict(tab_tree_item_data)

                tab_tree.append(tab_tree_item)

        tabs_payload_schema = cls(
            all_tabs=all_tabs,
            tab_tree=tab_tree,
        )

        tabs_payload_schema.additional_properties = d
        return tabs_payload_schema

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

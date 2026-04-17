from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.css_template_rest_api_get_user import CssTemplateRestApiGetUser
    from ..models.css_template_rest_api_get_user_1 import CssTemplateRestApiGetUser1


T = TypeVar("T", bound="CssTemplateRestApiGet")


@_attrs_define
class CssTemplateRestApiGet:
    """
    Attributes:
        changed_by (CssTemplateRestApiGetUser | Unset):
        changed_on_delta_humanized (Any | Unset):
        created_by (CssTemplateRestApiGetUser1 | Unset):
        css (None | str | Unset):
        id (int | Unset):
        template_name (None | str | Unset):
    """

    changed_by: CssTemplateRestApiGetUser | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    created_by: CssTemplateRestApiGetUser1 | Unset = UNSET
    css: None | str | Unset = UNSET
    id: int | Unset = UNSET
    template_name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on_delta_humanized = self.changed_on_delta_humanized

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        css: None | str | Unset
        if isinstance(self.css, Unset):
            css = UNSET
        else:
            css = self.css

        id = self.id

        template_name: None | str | Unset
        if isinstance(self.template_name, Unset):
            template_name = UNSET
        else:
            template_name = self.template_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if css is not UNSET:
            field_dict["css"] = css
        if id is not UNSET:
            field_dict["id"] = id
        if template_name is not UNSET:
            field_dict["template_name"] = template_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.css_template_rest_api_get_user import CssTemplateRestApiGetUser
        from ..models.css_template_rest_api_get_user_1 import CssTemplateRestApiGetUser1

        d = dict(src_dict)
        _changed_by = d.pop("changed_by", UNSET)
        changed_by: CssTemplateRestApiGetUser | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = CssTemplateRestApiGetUser.from_dict(_changed_by)

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: CssTemplateRestApiGetUser1 | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = CssTemplateRestApiGetUser1.from_dict(_created_by)

        def _parse_css(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        css = _parse_css(d.pop("css", UNSET))

        id = d.pop("id", UNSET)

        def _parse_template_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_name = _parse_template_name(d.pop("template_name", UNSET))

        css_template_rest_api_get = cls(
            changed_by=changed_by,
            changed_on_delta_humanized=changed_on_delta_humanized,
            created_by=created_by,
            css=css,
            id=id,
            template_name=template_name,
        )

        css_template_rest_api_get.additional_properties = d
        return css_template_rest_api_get

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

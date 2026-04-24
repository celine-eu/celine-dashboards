from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.annotation_layer_rest_api_get_list_user import AnnotationLayerRestApiGetListUser
    from ..models.annotation_layer_rest_api_get_list_user_1 import AnnotationLayerRestApiGetListUser1


T = TypeVar("T", bound="AnnotationLayerRestApiGetList")


@_attrs_define
class AnnotationLayerRestApiGetList:
    """
    Attributes:
        changed_by (AnnotationLayerRestApiGetListUser1 | Unset):
        changed_on (datetime.datetime | None | Unset):
        changed_on_delta_humanized (Any | Unset):
        created_by (AnnotationLayerRestApiGetListUser | Unset):
        created_on (datetime.datetime | None | Unset):
        descr (None | str | Unset):
        id (int | Unset):
        name (None | str | Unset):
    """

    changed_by: AnnotationLayerRestApiGetListUser1 | Unset = UNSET
    changed_on: datetime.datetime | None | Unset = UNSET
    changed_on_delta_humanized: Any | Unset = UNSET
    created_by: AnnotationLayerRestApiGetListUser | Unset = UNSET
    created_on: datetime.datetime | None | Unset = UNSET
    descr: None | str | Unset = UNSET
    id: int | Unset = UNSET
    name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        changed_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.changed_by, Unset):
            changed_by = self.changed_by.to_dict()

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        changed_on_delta_humanized = self.changed_on_delta_humanized

        created_by: dict[str, Any] | Unset = UNSET
        if not isinstance(self.created_by, Unset):
            created_by = self.created_by.to_dict()

        created_on: None | str | Unset
        if isinstance(self.created_on, Unset):
            created_on = UNSET
        elif isinstance(self.created_on, datetime.datetime):
            created_on = self.created_on.isoformat()
        else:
            created_on = self.created_on

        descr: None | str | Unset
        if isinstance(self.descr, Unset):
            descr = UNSET
        else:
            descr = self.descr

        id = self.id

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if changed_on_delta_humanized is not UNSET:
            field_dict["changed_on_delta_humanized"] = changed_on_delta_humanized
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_on is not UNSET:
            field_dict["created_on"] = created_on
        if descr is not UNSET:
            field_dict["descr"] = descr
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.annotation_layer_rest_api_get_list_user import AnnotationLayerRestApiGetListUser
        from ..models.annotation_layer_rest_api_get_list_user_1 import AnnotationLayerRestApiGetListUser1

        d = dict(src_dict)
        _changed_by = d.pop("changed_by", UNSET)
        changed_by: AnnotationLayerRestApiGetListUser1 | Unset
        if isinstance(_changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = AnnotationLayerRestApiGetListUser1.from_dict(_changed_by)

        def _parse_changed_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                changed_on_type_0 = isoparse(data)

                return changed_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        changed_on = _parse_changed_on(d.pop("changed_on", UNSET))

        changed_on_delta_humanized = d.pop("changed_on_delta_humanized", UNSET)

        _created_by = d.pop("created_by", UNSET)
        created_by: AnnotationLayerRestApiGetListUser | Unset
        if isinstance(_created_by, Unset):
            created_by = UNSET
        else:
            created_by = AnnotationLayerRestApiGetListUser.from_dict(_created_by)

        def _parse_created_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                created_on_type_0 = isoparse(data)

                return created_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        created_on = _parse_created_on(d.pop("created_on", UNSET))

        def _parse_descr(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        descr = _parse_descr(d.pop("descr", UNSET))

        id = d.pop("id", UNSET)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        annotation_layer_rest_api_get_list = cls(
            changed_by=changed_by,
            changed_on=changed_on,
            changed_on_delta_humanized=changed_on_delta_humanized,
            created_by=created_by,
            created_on=created_on,
            descr=descr,
            id=id,
            name=name,
        )

        annotation_layer_rest_api_get_list.additional_properties = d
        return annotation_layer_rest_api_get_list

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

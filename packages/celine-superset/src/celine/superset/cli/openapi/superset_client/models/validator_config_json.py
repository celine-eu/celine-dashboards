from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.validator_config_json_op import ValidatorConfigJSONOp, check_validator_config_json_op
from ..types import UNSET, Unset

T = TypeVar("T", bound="ValidatorConfigJSON")


@_attrs_define
class ValidatorConfigJSON:
    """
    Attributes:
        op (ValidatorConfigJSONOp | Unset): The operation to compare with a threshold to apply to the SQL output
        threshold (float | Unset):
    """

    op: ValidatorConfigJSONOp | Unset = UNSET
    threshold: float | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        op: str | Unset = UNSET
        if not isinstance(self.op, Unset):
            op = self.op

        threshold = self.threshold

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if op is not UNSET:
            field_dict["op"] = op
        if threshold is not UNSET:
            field_dict["threshold"] = threshold

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _op = d.pop("op", UNSET)
        op: ValidatorConfigJSONOp | Unset
        if isinstance(_op, Unset):
            op = UNSET
        else:
            op = check_validator_config_json_op(_op)

        threshold = d.pop("threshold", UNSET)

        validator_config_json = cls(
            op=op,
            threshold=threshold,
        )

        validator_config_json.additional_properties = d
        return validator_config_json

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

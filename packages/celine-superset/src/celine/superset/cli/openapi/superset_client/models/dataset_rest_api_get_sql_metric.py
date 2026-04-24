from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatasetRestApiGetSqlMetric")


@_attrs_define
class DatasetRestApiGetSqlMetric:
    """
    Attributes:
        expression (str):
        metric_name (str):
        changed_on (datetime.datetime | None | Unset):
        created_on (datetime.datetime | None | Unset):
        currency (Any | Unset):
        d3format (None | str | Unset):
        description (None | str | Unset):
        extra (None | str | Unset):
        id (int | Unset):
        metric_type (None | str | Unset):
        uuid (None | Unset | UUID):
        verbose_name (None | str | Unset):
        warning_text (None | str | Unset):
    """

    expression: str
    metric_name: str
    changed_on: datetime.datetime | None | Unset = UNSET
    created_on: datetime.datetime | None | Unset = UNSET
    currency: Any | Unset = UNSET
    d3format: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    extra: None | str | Unset = UNSET
    id: int | Unset = UNSET
    metric_type: None | str | Unset = UNSET
    uuid: None | Unset | UUID = UNSET
    verbose_name: None | str | Unset = UNSET
    warning_text: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        expression = self.expression

        metric_name = self.metric_name

        changed_on: None | str | Unset
        if isinstance(self.changed_on, Unset):
            changed_on = UNSET
        elif isinstance(self.changed_on, datetime.datetime):
            changed_on = self.changed_on.isoformat()
        else:
            changed_on = self.changed_on

        created_on: None | str | Unset
        if isinstance(self.created_on, Unset):
            created_on = UNSET
        elif isinstance(self.created_on, datetime.datetime):
            created_on = self.created_on.isoformat()
        else:
            created_on = self.created_on

        currency = self.currency

        d3format: None | str | Unset
        if isinstance(self.d3format, Unset):
            d3format = UNSET
        else:
            d3format = self.d3format

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        extra: None | str | Unset
        if isinstance(self.extra, Unset):
            extra = UNSET
        else:
            extra = self.extra

        id = self.id

        metric_type: None | str | Unset
        if isinstance(self.metric_type, Unset):
            metric_type = UNSET
        else:
            metric_type = self.metric_type

        uuid: None | str | Unset
        if isinstance(self.uuid, Unset):
            uuid = UNSET
        elif isinstance(self.uuid, UUID):
            uuid = str(self.uuid)
        else:
            uuid = self.uuid

        verbose_name: None | str | Unset
        if isinstance(self.verbose_name, Unset):
            verbose_name = UNSET
        else:
            verbose_name = self.verbose_name

        warning_text: None | str | Unset
        if isinstance(self.warning_text, Unset):
            warning_text = UNSET
        else:
            warning_text = self.warning_text

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "expression": expression,
                "metric_name": metric_name,
            }
        )
        if changed_on is not UNSET:
            field_dict["changed_on"] = changed_on
        if created_on is not UNSET:
            field_dict["created_on"] = created_on
        if currency is not UNSET:
            field_dict["currency"] = currency
        if d3format is not UNSET:
            field_dict["d3format"] = d3format
        if description is not UNSET:
            field_dict["description"] = description
        if extra is not UNSET:
            field_dict["extra"] = extra
        if id is not UNSET:
            field_dict["id"] = id
        if metric_type is not UNSET:
            field_dict["metric_type"] = metric_type
        if uuid is not UNSET:
            field_dict["uuid"] = uuid
        if verbose_name is not UNSET:
            field_dict["verbose_name"] = verbose_name
        if warning_text is not UNSET:
            field_dict["warning_text"] = warning_text

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        expression = d.pop("expression")

        metric_name = d.pop("metric_name")

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

        currency = d.pop("currency", UNSET)

        def _parse_d3format(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        d3format = _parse_d3format(d.pop("d3format", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_extra(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extra = _parse_extra(d.pop("extra", UNSET))

        id = d.pop("id", UNSET)

        def _parse_metric_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        metric_type = _parse_metric_type(d.pop("metric_type", UNSET))

        def _parse_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                uuid_type_0 = UUID(data)

                return uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        uuid = _parse_uuid(d.pop("uuid", UNSET))

        def _parse_verbose_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        verbose_name = _parse_verbose_name(d.pop("verbose_name", UNSET))

        def _parse_warning_text(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        warning_text = _parse_warning_text(d.pop("warning_text", UNSET))

        dataset_rest_api_get_sql_metric = cls(
            expression=expression,
            metric_name=metric_name,
            changed_on=changed_on,
            created_on=created_on,
            currency=currency,
            d3format=d3format,
            description=description,
            extra=extra,
            id=id,
            metric_type=metric_type,
            uuid=uuid,
            verbose_name=verbose_name,
            warning_text=warning_text,
        )

        dataset_rest_api_get_sql_metric.additional_properties = d
        return dataset_rest_api_get_sql_metric

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

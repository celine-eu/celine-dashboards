from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.annotation_layer_annotation_type import (
    AnnotationLayerAnnotationType,
    check_annotation_layer_annotation_type,
)
from ..models.annotation_layer_opacity_type_1 import AnnotationLayerOpacityType1, check_annotation_layer_opacity_type_1
from ..models.annotation_layer_opacity_type_2_type_1 import (
    AnnotationLayerOpacityType2Type1,
    check_annotation_layer_opacity_type_2_type_1,
)
from ..models.annotation_layer_opacity_type_3_type_1 import (
    AnnotationLayerOpacityType3Type1,
    check_annotation_layer_opacity_type_3_type_1,
)
from ..models.annotation_layer_source_type import AnnotationLayerSourceType, check_annotation_layer_source_type
from ..models.annotation_layer_style import AnnotationLayerStyle, check_annotation_layer_style
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.annotation_layer_overrides_type_0 import AnnotationLayerOverridesType0


T = TypeVar("T", bound="AnnotationLayer")


@_attrs_define
class AnnotationLayer:
    """
    Attributes:
        name (str): Name of layer
        show (bool): Should the layer be shown
        show_markers (bool): Should markers be shown. Only applies to line annotations.
        value (Any): For formula annotations, this contains the formula. For other types, this is the primary key of the
            source object.
        annotation_type (AnnotationLayerAnnotationType | Unset): Type of annotation layer
        color (None | str | Unset): Layer color
        description_columns (list[str] | Unset): Columns to use as the description. If none are provided, all will be
            shown.
        hide_line (bool | None | Unset): Should line be hidden. Only applies to line annotations
        interval_end_column (None | str | Unset): Column containing end of interval. Only applies to interval layers
        opacity (AnnotationLayerOpacityType1 | AnnotationLayerOpacityType2Type1 | AnnotationLayerOpacityType3Type1 |
            None | Unset): Opacity of layer
        overrides (AnnotationLayerOverridesType0 | None | Unset): which properties should be overridable
        show_label (bool | None | Unset): Should the label always be shown
        source_type (AnnotationLayerSourceType | Unset): Type of source for annotation data
        style (AnnotationLayerStyle | Unset): Line style. Only applies to time-series annotations
        time_column (None | str | Unset): Column with event date or interval start date
        title_column (None | str | Unset): Column with title
        width (float | Unset): Width of annotation line
    """

    name: str
    show: bool
    show_markers: bool
    value: Any
    annotation_type: AnnotationLayerAnnotationType | Unset = UNSET
    color: None | str | Unset = UNSET
    description_columns: list[str] | Unset = UNSET
    hide_line: bool | None | Unset = UNSET
    interval_end_column: None | str | Unset = UNSET
    opacity: (
        AnnotationLayerOpacityType1 | AnnotationLayerOpacityType2Type1 | AnnotationLayerOpacityType3Type1 | None | Unset
    ) = UNSET
    overrides: AnnotationLayerOverridesType0 | None | Unset = UNSET
    show_label: bool | None | Unset = UNSET
    source_type: AnnotationLayerSourceType | Unset = UNSET
    style: AnnotationLayerStyle | Unset = UNSET
    time_column: None | str | Unset = UNSET
    title_column: None | str | Unset = UNSET
    width: float | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.annotation_layer_overrides_type_0 import AnnotationLayerOverridesType0

        name = self.name

        show = self.show

        show_markers = self.show_markers

        value = self.value

        annotation_type: str | Unset = UNSET
        if not isinstance(self.annotation_type, Unset):
            annotation_type = self.annotation_type

        color: None | str | Unset
        if isinstance(self.color, Unset):
            color = UNSET
        else:
            color = self.color

        description_columns: list[str] | Unset = UNSET
        if not isinstance(self.description_columns, Unset):
            description_columns = self.description_columns

        hide_line: bool | None | Unset
        if isinstance(self.hide_line, Unset):
            hide_line = UNSET
        else:
            hide_line = self.hide_line

        interval_end_column: None | str | Unset
        if isinstance(self.interval_end_column, Unset):
            interval_end_column = UNSET
        else:
            interval_end_column = self.interval_end_column

        opacity: None | str | Unset
        if isinstance(self.opacity, Unset):
            opacity = UNSET
        elif isinstance(self.opacity, str):
            opacity = self.opacity
        elif isinstance(self.opacity, str):
            opacity = self.opacity
        elif isinstance(self.opacity, str):
            opacity = self.opacity
        else:
            opacity = self.opacity

        overrides: dict[str, Any] | None | Unset
        if isinstance(self.overrides, Unset):
            overrides = UNSET
        elif isinstance(self.overrides, AnnotationLayerOverridesType0):
            overrides = self.overrides.to_dict()
        else:
            overrides = self.overrides

        show_label: bool | None | Unset
        if isinstance(self.show_label, Unset):
            show_label = UNSET
        else:
            show_label = self.show_label

        source_type: str | Unset = UNSET
        if not isinstance(self.source_type, Unset):
            source_type = self.source_type

        style: str | Unset = UNSET
        if not isinstance(self.style, Unset):
            style = self.style

        time_column: None | str | Unset
        if isinstance(self.time_column, Unset):
            time_column = UNSET
        else:
            time_column = self.time_column

        title_column: None | str | Unset
        if isinstance(self.title_column, Unset):
            title_column = UNSET
        else:
            title_column = self.title_column

        width = self.width

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "show": show,
                "showMarkers": show_markers,
                "value": value,
            }
        )
        if annotation_type is not UNSET:
            field_dict["annotationType"] = annotation_type
        if color is not UNSET:
            field_dict["color"] = color
        if description_columns is not UNSET:
            field_dict["descriptionColumns"] = description_columns
        if hide_line is not UNSET:
            field_dict["hideLine"] = hide_line
        if interval_end_column is not UNSET:
            field_dict["intervalEndColumn"] = interval_end_column
        if opacity is not UNSET:
            field_dict["opacity"] = opacity
        if overrides is not UNSET:
            field_dict["overrides"] = overrides
        if show_label is not UNSET:
            field_dict["showLabel"] = show_label
        if source_type is not UNSET:
            field_dict["sourceType"] = source_type
        if style is not UNSET:
            field_dict["style"] = style
        if time_column is not UNSET:
            field_dict["timeColumn"] = time_column
        if title_column is not UNSET:
            field_dict["titleColumn"] = title_column
        if width is not UNSET:
            field_dict["width"] = width

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.annotation_layer_overrides_type_0 import AnnotationLayerOverridesType0

        d = dict(src_dict)
        name = d.pop("name")

        show = d.pop("show")

        show_markers = d.pop("showMarkers")

        value = d.pop("value")

        _annotation_type = d.pop("annotationType", UNSET)
        annotation_type: AnnotationLayerAnnotationType | Unset
        if isinstance(_annotation_type, Unset):
            annotation_type = UNSET
        else:
            annotation_type = check_annotation_layer_annotation_type(_annotation_type)

        def _parse_color(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        color = _parse_color(d.pop("color", UNSET))

        description_columns = cast(list[str], d.pop("descriptionColumns", UNSET))

        def _parse_hide_line(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        hide_line = _parse_hide_line(d.pop("hideLine", UNSET))

        def _parse_interval_end_column(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        interval_end_column = _parse_interval_end_column(d.pop("intervalEndColumn", UNSET))

        def _parse_opacity(
            data: object,
        ) -> (
            AnnotationLayerOpacityType1
            | AnnotationLayerOpacityType2Type1
            | AnnotationLayerOpacityType3Type1
            | None
            | Unset
        ):
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                opacity_type_1 = check_annotation_layer_opacity_type_1(data)

                return opacity_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, str):
                    raise TypeError()
                opacity_type_2_type_1 = check_annotation_layer_opacity_type_2_type_1(data)

                return opacity_type_2_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, str):
                    raise TypeError()
                opacity_type_3_type_1 = check_annotation_layer_opacity_type_3_type_1(data)

                return opacity_type_3_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(
                AnnotationLayerOpacityType1
                | AnnotationLayerOpacityType2Type1
                | AnnotationLayerOpacityType3Type1
                | None
                | Unset,
                data,
            )

        opacity = _parse_opacity(d.pop("opacity", UNSET))

        def _parse_overrides(data: object) -> AnnotationLayerOverridesType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                overrides_type_0 = AnnotationLayerOverridesType0.from_dict(data)

                return overrides_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AnnotationLayerOverridesType0 | None | Unset, data)

        overrides = _parse_overrides(d.pop("overrides", UNSET))

        def _parse_show_label(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        show_label = _parse_show_label(d.pop("showLabel", UNSET))

        _source_type = d.pop("sourceType", UNSET)
        source_type: AnnotationLayerSourceType | Unset
        if isinstance(_source_type, Unset):
            source_type = UNSET
        else:
            source_type = check_annotation_layer_source_type(_source_type)

        _style = d.pop("style", UNSET)
        style: AnnotationLayerStyle | Unset
        if isinstance(_style, Unset):
            style = UNSET
        else:
            style = check_annotation_layer_style(_style)

        def _parse_time_column(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        time_column = _parse_time_column(d.pop("timeColumn", UNSET))

        def _parse_title_column(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title_column = _parse_title_column(d.pop("titleColumn", UNSET))

        width = d.pop("width", UNSET)

        annotation_layer = cls(
            name=name,
            show=show,
            show_markers=show_markers,
            value=value,
            annotation_type=annotation_type,
            color=color,
            description_columns=description_columns,
            hide_line=hide_line,
            interval_end_column=interval_end_column,
            opacity=opacity,
            overrides=overrides,
            show_label=show_label,
            source_type=source_type,
            style=style,
            time_column=time_column,
            title_column=title_column,
            width=width,
        )

        annotation_layer.additional_properties = d
        return annotation_layer

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

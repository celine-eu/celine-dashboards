from typing import Literal, cast

AnnotationLayerStyle = Literal["dashed", "dotted", "longDashed", "solid"]

ANNOTATION_LAYER_STYLE_VALUES: set[AnnotationLayerStyle] = {
    "dashed",
    "dotted",
    "longDashed",
    "solid",
}


def check_annotation_layer_style(value: str) -> AnnotationLayerStyle:
    if value in ANNOTATION_LAYER_STYLE_VALUES:
        return cast(AnnotationLayerStyle, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {ANNOTATION_LAYER_STYLE_VALUES!r}")

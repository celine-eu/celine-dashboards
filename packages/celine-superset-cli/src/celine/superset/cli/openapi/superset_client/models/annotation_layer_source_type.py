from typing import Literal, cast

AnnotationLayerSourceType = Literal["", "line", "NATIVE", "table"]

ANNOTATION_LAYER_SOURCE_TYPE_VALUES: set[AnnotationLayerSourceType] = {
    "",
    "line",
    "NATIVE",
    "table",
}


def check_annotation_layer_source_type(value: str) -> AnnotationLayerSourceType:
    if value in ANNOTATION_LAYER_SOURCE_TYPE_VALUES:
        return cast(AnnotationLayerSourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {ANNOTATION_LAYER_SOURCE_TYPE_VALUES!r}")

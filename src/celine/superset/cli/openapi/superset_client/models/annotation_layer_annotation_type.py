from typing import Literal, cast

AnnotationLayerAnnotationType = Literal["EVENT", "FORMULA", "INTERVAL", "TIME_SERIES"]

ANNOTATION_LAYER_ANNOTATION_TYPE_VALUES: set[AnnotationLayerAnnotationType] = {
    "EVENT",
    "FORMULA",
    "INTERVAL",
    "TIME_SERIES",
}


def check_annotation_layer_annotation_type(value: str) -> AnnotationLayerAnnotationType:
    if value in ANNOTATION_LAYER_ANNOTATION_TYPE_VALUES:
        return cast(AnnotationLayerAnnotationType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {ANNOTATION_LAYER_ANNOTATION_TYPE_VALUES!r}")

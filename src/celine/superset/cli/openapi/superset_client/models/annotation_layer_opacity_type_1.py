from typing import Literal, cast

AnnotationLayerOpacityType1 = Literal["", "opacityHigh", "opacityLow", "opacityMedium"]

ANNOTATION_LAYER_OPACITY_TYPE_1_VALUES: set[AnnotationLayerOpacityType1] = {
    "",
    "opacityHigh",
    "opacityLow",
    "opacityMedium",
}


def check_annotation_layer_opacity_type_1(value: str) -> AnnotationLayerOpacityType1:
    if value in ANNOTATION_LAYER_OPACITY_TYPE_1_VALUES:
        return cast(AnnotationLayerOpacityType1, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {ANNOTATION_LAYER_OPACITY_TYPE_1_VALUES!r}")

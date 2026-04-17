from typing import Literal, cast

AnnotationLayerOpacityType2Type1 = Literal["", "opacityHigh", "opacityLow", "opacityMedium"]

ANNOTATION_LAYER_OPACITY_TYPE_2_TYPE_1_VALUES: set[AnnotationLayerOpacityType2Type1] = {
    "",
    "opacityHigh",
    "opacityLow",
    "opacityMedium",
}


def check_annotation_layer_opacity_type_2_type_1(value: str) -> AnnotationLayerOpacityType2Type1:
    if value in ANNOTATION_LAYER_OPACITY_TYPE_2_TYPE_1_VALUES:
        return cast(AnnotationLayerOpacityType2Type1, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {ANNOTATION_LAYER_OPACITY_TYPE_2_TYPE_1_VALUES!r}")

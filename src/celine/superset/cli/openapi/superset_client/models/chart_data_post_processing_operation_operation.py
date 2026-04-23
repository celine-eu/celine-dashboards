from typing import Literal, cast

ChartDataPostProcessingOperationOperation = Literal[
    "aggregate",
    "boxplot",
    "compare",
    "contribution",
    "cum",
    "diff",
    "escape_separator",
    "flatten",
    "geodetic_parse",
    "geohash_decode",
    "geohash_encode",
    "histogram",
    "pivot",
    "prophet",
    "rank",
    "rename",
    "resample",
    "rolling",
    "select",
    "sort",
    "unescape_separator",
]

CHART_DATA_POST_PROCESSING_OPERATION_OPERATION_VALUES: set[ChartDataPostProcessingOperationOperation] = {
    "aggregate",
    "boxplot",
    "compare",
    "contribution",
    "cum",
    "diff",
    "escape_separator",
    "flatten",
    "geodetic_parse",
    "geohash_decode",
    "geohash_encode",
    "histogram",
    "pivot",
    "prophet",
    "rank",
    "rename",
    "resample",
    "rolling",
    "select",
    "sort",
    "unescape_separator",
}


def check_chart_data_post_processing_operation_operation(value: str) -> ChartDataPostProcessingOperationOperation:
    if value in CHART_DATA_POST_PROCESSING_OPERATION_OPERATION_VALUES:
        return cast(ChartDataPostProcessingOperationOperation, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {CHART_DATA_POST_PROCESSING_OPERATION_OPERATION_VALUES!r}"
    )

from typing import Literal, cast

UploadPostSchemaAlreadyExists = Literal["append", "fail", "replace"]

UPLOAD_POST_SCHEMA_ALREADY_EXISTS_VALUES: set[UploadPostSchemaAlreadyExists] = {
    "append",
    "fail",
    "replace",
}


def check_upload_post_schema_already_exists(value: str) -> UploadPostSchemaAlreadyExists:
    if value in UPLOAD_POST_SCHEMA_ALREADY_EXISTS_VALUES:
        return cast(UploadPostSchemaAlreadyExists, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {UPLOAD_POST_SCHEMA_ALREADY_EXISTS_VALUES!r}")

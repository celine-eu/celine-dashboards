from typing import Literal, cast

UploadPostSchemaType = Literal["columnar", "csv", "excel"]

UPLOAD_POST_SCHEMA_TYPE_VALUES: set[UploadPostSchemaType] = {
    "columnar",
    "csv",
    "excel",
}


def check_upload_post_schema_type(value: str) -> UploadPostSchemaType:
    if value in UPLOAD_POST_SCHEMA_TYPE_VALUES:
        return cast(UploadPostSchemaType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {UPLOAD_POST_SCHEMA_TYPE_VALUES!r}")

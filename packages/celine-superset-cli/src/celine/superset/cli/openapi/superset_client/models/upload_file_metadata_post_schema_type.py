from typing import Literal, cast

UploadFileMetadataPostSchemaType = Literal["columnar", "csv", "excel"]

UPLOAD_FILE_METADATA_POST_SCHEMA_TYPE_VALUES: set[UploadFileMetadataPostSchemaType] = {
    "columnar",
    "csv",
    "excel",
}


def check_upload_file_metadata_post_schema_type(value: str) -> UploadFileMetadataPostSchemaType:
    if value in UPLOAD_FILE_METADATA_POST_SCHEMA_TYPE_VALUES:
        return cast(UploadFileMetadataPostSchemaType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {UPLOAD_FILE_METADATA_POST_SCHEMA_TYPE_VALUES!r}")

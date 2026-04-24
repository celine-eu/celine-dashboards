from typing import Literal, cast

FolderType = Literal["column", "folder", "metric"]

FOLDER_TYPE_VALUES: set[FolderType] = {
    "column",
    "folder",
    "metric",
}


def check_folder_type(value: str) -> FolderType:
    if value in FOLDER_TYPE_VALUES:
        return cast(FolderType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {FOLDER_TYPE_VALUES!r}")

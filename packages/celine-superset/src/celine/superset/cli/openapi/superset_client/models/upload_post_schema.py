from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from .. import types
from ..models.upload_post_schema_already_exists import (
    UploadPostSchemaAlreadyExists,
    check_upload_post_schema_already_exists,
)
from ..models.upload_post_schema_type import UploadPostSchemaType, check_upload_post_schema_type
from ..types import UNSET, Unset

T = TypeVar("T", bound="UploadPostSchema")


@_attrs_define
class UploadPostSchema:
    """
    Attributes:
        file (str): The file to upload
        table_name (str): The name of the table to be created/appended
        type_ (UploadPostSchemaType): File type to upload
        already_exists (UploadPostSchemaAlreadyExists | Unset): What to do if the table already exists accepts: fail,
            replace, append Default: 'fail'.
        column_data_types (str | Unset): [CSV only] A dictionary with column names and their data types if you need to
            change the defaults. Example: {'user_id':'int'}. Check Python Pandas library for supported data types
        column_dates (list[str] | Unset): [CSV and Excel only] A list of column names that should be parsed as dates.
            Example: date,timestamp
        columns_read (list[str] | Unset): A List of the column names that should be read
        dataframe_index (bool | Unset): Write dataframe index as a column.
        day_first (bool | Unset): [CSV only] DD/MM format dates, international and European format
        decimal_character (str | Unset): [CSV and Excel only] Character to recognize as decimal point. Default is '.'
        delimiter (str | Unset): [CSV only] The character used to separate values in the CSV file (e.g., a comma,
            semicolon, or tab).
        header_row (int | Unset): [CSV and Excel only] Row containing the headers to use as column names (0 is first
            line of data). Leave empty if there is no header row.
        index_column (str | Unset): [CSV and Excel only] Column to use as the row labels of the dataframe. Leave empty
            if no index column
        index_label (str | Unset): Index label for index column.
        null_values (list[str] | Unset): [CSV and Excel only] A list of strings that should be treated as null.
            Examples: '' for empty strings, 'None', 'N/A', Warning: Hive database supports only a single value
        rows_to_read (int | None | Unset): [CSV and Excel only] Number of rows to read from the file. If None, reads all
            rows.
        schema (str | Unset): The schema to upload the data file to.
        sheet_name (str | Unset): [Excel only]] Strings used for sheet names (default is the first sheet).
        skip_blank_lines (bool | Unset): [CSV only] Skip blank lines in the CSV file.
        skip_initial_space (bool | Unset): [CSV only] Skip spaces after delimiter.
        skip_rows (int | Unset): [CSV and Excel only] Number of rows to skip at start of file.
    """

    file: str
    table_name: str
    type_: UploadPostSchemaType
    already_exists: UploadPostSchemaAlreadyExists | Unset = "fail"
    column_data_types: str | Unset = UNSET
    column_dates: list[str] | Unset = UNSET
    columns_read: list[str] | Unset = UNSET
    dataframe_index: bool | Unset = UNSET
    day_first: bool | Unset = UNSET
    decimal_character: str | Unset = UNSET
    delimiter: str | Unset = UNSET
    header_row: int | Unset = UNSET
    index_column: str | Unset = UNSET
    index_label: str | Unset = UNSET
    null_values: list[str] | Unset = UNSET
    rows_to_read: int | None | Unset = UNSET
    schema: str | Unset = UNSET
    sheet_name: str | Unset = UNSET
    skip_blank_lines: bool | Unset = UNSET
    skip_initial_space: bool | Unset = UNSET
    skip_rows: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file = self.file

        table_name = self.table_name

        type_: str = self.type_

        already_exists: str | Unset = UNSET
        if not isinstance(self.already_exists, Unset):
            already_exists = self.already_exists

        column_data_types = self.column_data_types

        column_dates: list[str] | Unset = UNSET
        if not isinstance(self.column_dates, Unset):
            column_dates = self.column_dates

        columns_read: list[str] | Unset = UNSET
        if not isinstance(self.columns_read, Unset):
            columns_read = self.columns_read

        dataframe_index = self.dataframe_index

        day_first = self.day_first

        decimal_character = self.decimal_character

        delimiter = self.delimiter

        header_row = self.header_row

        index_column = self.index_column

        index_label = self.index_label

        null_values: list[str] | Unset = UNSET
        if not isinstance(self.null_values, Unset):
            null_values = self.null_values

        rows_to_read: int | None | Unset
        if isinstance(self.rows_to_read, Unset):
            rows_to_read = UNSET
        else:
            rows_to_read = self.rows_to_read

        schema = self.schema

        sheet_name = self.sheet_name

        skip_blank_lines = self.skip_blank_lines

        skip_initial_space = self.skip_initial_space

        skip_rows = self.skip_rows

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file": file,
                "table_name": table_name,
                "type": type_,
            }
        )
        if already_exists is not UNSET:
            field_dict["already_exists"] = already_exists
        if column_data_types is not UNSET:
            field_dict["column_data_types"] = column_data_types
        if column_dates is not UNSET:
            field_dict["column_dates"] = column_dates
        if columns_read is not UNSET:
            field_dict["columns_read"] = columns_read
        if dataframe_index is not UNSET:
            field_dict["dataframe_index"] = dataframe_index
        if day_first is not UNSET:
            field_dict["day_first"] = day_first
        if decimal_character is not UNSET:
            field_dict["decimal_character"] = decimal_character
        if delimiter is not UNSET:
            field_dict["delimiter"] = delimiter
        if header_row is not UNSET:
            field_dict["header_row"] = header_row
        if index_column is not UNSET:
            field_dict["index_column"] = index_column
        if index_label is not UNSET:
            field_dict["index_label"] = index_label
        if null_values is not UNSET:
            field_dict["null_values"] = null_values
        if rows_to_read is not UNSET:
            field_dict["rows_to_read"] = rows_to_read
        if schema is not UNSET:
            field_dict["schema"] = schema
        if sheet_name is not UNSET:
            field_dict["sheet_name"] = sheet_name
        if skip_blank_lines is not UNSET:
            field_dict["skip_blank_lines"] = skip_blank_lines
        if skip_initial_space is not UNSET:
            field_dict["skip_initial_space"] = skip_initial_space
        if skip_rows is not UNSET:
            field_dict["skip_rows"] = skip_rows

        return field_dict

    def to_multipart(self) -> types.RequestFiles:
        files: types.RequestFiles = []

        files.append(("file", (None, str(self.file).encode(), "text/plain")))

        files.append(("table_name", (None, str(self.table_name).encode(), "text/plain")))

        files.append(("type", (None, str(self.type_).encode(), "text/plain")))

        if not isinstance(self.already_exists, Unset):
            files.append(("already_exists", (None, str(self.already_exists).encode(), "text/plain")))

        if not isinstance(self.column_data_types, Unset):
            files.append(("column_data_types", (None, str(self.column_data_types).encode(), "text/plain")))

        if not isinstance(self.column_dates, Unset):
            for column_dates_item_element in self.column_dates:
                files.append(("column_dates", (None, str(column_dates_item_element).encode(), "text/plain")))

        if not isinstance(self.columns_read, Unset):
            for columns_read_item_element in self.columns_read:
                files.append(("columns_read", (None, str(columns_read_item_element).encode(), "text/plain")))

        if not isinstance(self.dataframe_index, Unset):
            files.append(("dataframe_index", (None, str(self.dataframe_index).encode(), "text/plain")))

        if not isinstance(self.day_first, Unset):
            files.append(("day_first", (None, str(self.day_first).encode(), "text/plain")))

        if not isinstance(self.decimal_character, Unset):
            files.append(("decimal_character", (None, str(self.decimal_character).encode(), "text/plain")))

        if not isinstance(self.delimiter, Unset):
            files.append(("delimiter", (None, str(self.delimiter).encode(), "text/plain")))

        if not isinstance(self.header_row, Unset):
            files.append(("header_row", (None, str(self.header_row).encode(), "text/plain")))

        if not isinstance(self.index_column, Unset):
            files.append(("index_column", (None, str(self.index_column).encode(), "text/plain")))

        if not isinstance(self.index_label, Unset):
            files.append(("index_label", (None, str(self.index_label).encode(), "text/plain")))

        if not isinstance(self.null_values, Unset):
            for null_values_item_element in self.null_values:
                files.append(("null_values", (None, str(null_values_item_element).encode(), "text/plain")))

        if not isinstance(self.rows_to_read, Unset):
            if isinstance(self.rows_to_read, int):
                files.append(("rows_to_read", (None, str(self.rows_to_read).encode(), "text/plain")))
            else:
                files.append(("rows_to_read", (None, str(self.rows_to_read).encode(), "text/plain")))

        if not isinstance(self.schema, Unset):
            files.append(("schema", (None, str(self.schema).encode(), "text/plain")))

        if not isinstance(self.sheet_name, Unset):
            files.append(("sheet_name", (None, str(self.sheet_name).encode(), "text/plain")))

        if not isinstance(self.skip_blank_lines, Unset):
            files.append(("skip_blank_lines", (None, str(self.skip_blank_lines).encode(), "text/plain")))

        if not isinstance(self.skip_initial_space, Unset):
            files.append(("skip_initial_space", (None, str(self.skip_initial_space).encode(), "text/plain")))

        if not isinstance(self.skip_rows, Unset):
            files.append(("skip_rows", (None, str(self.skip_rows).encode(), "text/plain")))

        for prop_name, prop in self.additional_properties.items():
            files.append((prop_name, (None, str(prop).encode(), "text/plain")))

        return files

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file = d.pop("file")

        table_name = d.pop("table_name")

        type_ = check_upload_post_schema_type(d.pop("type"))

        _already_exists = d.pop("already_exists", UNSET)
        already_exists: UploadPostSchemaAlreadyExists | Unset
        if isinstance(_already_exists, Unset):
            already_exists = UNSET
        else:
            already_exists = check_upload_post_schema_already_exists(_already_exists)

        column_data_types = d.pop("column_data_types", UNSET)

        column_dates = cast(list[str], d.pop("column_dates", UNSET))

        columns_read = cast(list[str], d.pop("columns_read", UNSET))

        dataframe_index = d.pop("dataframe_index", UNSET)

        day_first = d.pop("day_first", UNSET)

        decimal_character = d.pop("decimal_character", UNSET)

        delimiter = d.pop("delimiter", UNSET)

        header_row = d.pop("header_row", UNSET)

        index_column = d.pop("index_column", UNSET)

        index_label = d.pop("index_label", UNSET)

        null_values = cast(list[str], d.pop("null_values", UNSET))

        def _parse_rows_to_read(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rows_to_read = _parse_rows_to_read(d.pop("rows_to_read", UNSET))

        schema = d.pop("schema", UNSET)

        sheet_name = d.pop("sheet_name", UNSET)

        skip_blank_lines = d.pop("skip_blank_lines", UNSET)

        skip_initial_space = d.pop("skip_initial_space", UNSET)

        skip_rows = d.pop("skip_rows", UNSET)

        upload_post_schema = cls(
            file=file,
            table_name=table_name,
            type_=type_,
            already_exists=already_exists,
            column_data_types=column_data_types,
            column_dates=column_dates,
            columns_read=columns_read,
            dataframe_index=dataframe_index,
            day_first=day_first,
            decimal_character=decimal_character,
            delimiter=delimiter,
            header_row=header_row,
            index_column=index_column,
            index_label=index_label,
            null_values=null_values,
            rows_to_read=rows_to_read,
            schema=schema,
            sheet_name=sheet_name,
            skip_blank_lines=skip_blank_lines,
            skip_initial_space=skip_initial_space,
            skip_rows=skip_rows,
        )

        upload_post_schema.additional_properties = d
        return upload_post_schema

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

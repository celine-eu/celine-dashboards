from typing import Literal, cast

GetApiV1DashboardPkScreenshotDigestDownloadFormat = Literal["pdf", "png"]

GET_API_V1_DASHBOARD_PK_SCREENSHOT_DIGEST_DOWNLOAD_FORMAT_VALUES: set[
    GetApiV1DashboardPkScreenshotDigestDownloadFormat
] = {
    "pdf",
    "png",
}


def check_get_api_v1_dashboard_pk_screenshot_digest_download_format(
    value: str,
) -> GetApiV1DashboardPkScreenshotDigestDownloadFormat:
    if value in GET_API_V1_DASHBOARD_PK_SCREENSHOT_DIGEST_DOWNLOAD_FORMAT_VALUES:
        return cast(GetApiV1DashboardPkScreenshotDigestDownloadFormat, value)
    raise TypeError(
        f"Unexpected value {value!r}. Expected one of {GET_API_V1_DASHBOARD_PK_SCREENSHOT_DIGEST_DOWNLOAD_FORMAT_VALUES!r}"
    )

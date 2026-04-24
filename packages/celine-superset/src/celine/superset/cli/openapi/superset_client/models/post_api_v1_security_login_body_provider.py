from typing import Literal, cast

PostApiV1SecurityLoginBodyProvider = Literal["db", "ldap"]

POST_API_V1_SECURITY_LOGIN_BODY_PROVIDER_VALUES: set[PostApiV1SecurityLoginBodyProvider] = {
    "db",
    "ldap",
}


def check_post_api_v1_security_login_body_provider(value: str) -> PostApiV1SecurityLoginBodyProvider:
    if value in POST_API_V1_SECURITY_LOGIN_BODY_PROVIDER_VALUES:
        return cast(PostApiV1SecurityLoginBodyProvider, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {POST_API_V1_SECURITY_LOGIN_BODY_PROVIDER_VALUES!r}")

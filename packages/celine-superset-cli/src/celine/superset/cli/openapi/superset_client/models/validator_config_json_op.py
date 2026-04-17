from typing import Literal, cast

ValidatorConfigJSONOp = Literal["!=", "<", "<=", "==", ">", ">="]

VALIDATOR_CONFIG_JSON_OP_VALUES: set[ValidatorConfigJSONOp] = {
    "!=",
    "<",
    "<=",
    "==",
    ">",
    ">=",
}


def check_validator_config_json_op(value: str) -> ValidatorConfigJSONOp:
    if value in VALIDATOR_CONFIG_JSON_OP_VALUES:
        return cast(ValidatorConfigJSONOp, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {VALIDATOR_CONFIG_JSON_OP_VALUES!r}")

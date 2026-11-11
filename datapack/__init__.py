"""多方日志共享的作用域假名化库。

公开接口只暴露作用域、键环、策略校验与转换引擎及导出编排；密钥字节与原值
对照表都不会被序列化到任何结果、进度或异常中。
"""
from .pseudonym import (
    ALGORITHM,
    ENCODING,
    FULL_LENGTH,
    LABEL,
    MIN_KEY_BYTES,
    MIN_LENGTH,
    Engine,
    Keyring,
    PseudonymError,
    Scope,
    TransformFailure,
    derive_pseudonym,
    encode_message,
    scope_allowed,
    validate_policy,
)
from .pipeline import export_package, generate_key_file, load_bundle

__all__ = [
    "ALGORITHM",
    "ENCODING",
    "FULL_LENGTH",
    "LABEL",
    "MIN_KEY_BYTES",
    "MIN_LENGTH",
    "Engine",
    "Keyring",
    "PseudonymError",
    "Scope",
    "TransformFailure",
    "derive_pseudonym",
    "encode_message",
    "scope_allowed",
    "validate_policy",
    "export_package",
    "generate_key_file",
    "load_bundle",
]

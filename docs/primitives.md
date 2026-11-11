# 已有领域原语

import struct

源码中的函数是可独立调用的纯计算或内容对象操作；tests/domain_checks.py包含输入示例。它们不隐式读取整个样本包，也不自动完成跨来源业务加工。调用者可在自己的应用层组合这些接口，输入字段约定以domain.md为准。

作用域假名的公开入口位于datapack.pseudonym：Scope、Keyring、validate_policy、Engine、derive_pseudonym。它们在内存中完成派生与校验，密钥只来自调用者载入的文件；导出编排与文件清理见datapack.pipeline。


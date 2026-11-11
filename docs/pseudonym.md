# 作用域假名化与键轮换

## 目标与边界

多城市合作团队只共享同一份明确合同内的车队日志。假名化的目的不是隐藏业务
值，而是让交付包内的主键与引用在**指定作用域**内可连接、跨作用域不可连接：

- 同一作用域内，相同实体稳定得到相同假名。
- 合作方、项目、周窗口、实体类型或键版本任一不同，假名即不同。
- 输出只含假名、允许保留的业务值和列结构，不含原值对照表。
- 禁止字段在输出前删除；车间代码等非标识业务值原样保留。

作用域维度固定为 `partner`、`project`、`window`、`key_version`，实体类型在
键派生时追加，共五个维度，缺一即视为不同作用域。

## 派生方式

使用标准 HMAC-SHA256，密钥为键文件中对应版本的原始字节。消息采用有边界的
长度前缀编码（每段 UTF-8 字节前加 u32 大端长度），避免分段歧义：

```
label || partner || project || window || entity || key_version || normalized_value
```

`label` 固定为 `datapack.pseudonym/v1`，用于算法与用途隔离。规范化后的原值在
编码前不拼接分隔符，因此 `["ab","c"]` 与 `["a","bc"]` 不会产生相同消息。

默认输出 64 个十六进制字符（完整 256 位摘要）。允许在策略表级设置
`pseudonym_length`（2–64）以适配短标识场景；截断会提高碰撞概率，因此**任何
截断碰撞都直接使整次交付失败**，绝不随机改号或重试。

## 策略文件

策略文件同时声明本次共享合同允许的作用域，以及每张表的字段动作。顶层的
`scopes` 是白名单：只有合作方、项目、周窗口、键版本四项完全匹配才允许导出；
省略 `scopes` 时（例如库内单元测试）不做白名单限制。为兼容已有调用，纯表
数组格式仍可使用。

```json
{
  "scopes": [
    {"partner": "P1", "project": "traffic-data", "window": "2026-W45", "key_version": "v1"}
  ],
  "tables": [
    {
      "table": "vehicles",
      "primary": "vehicle_id",
      "fields": {
        "vehicle_id": {"action": "id", "entity": "vehicle", "normalize": "upper_ascii"},
        "operator_id": {
          "action": "ref", "entity": "operator", "normalize": "exact",
          "ref_table": "operators", "ref_field": "operator_id"
        },
        "workshop": {"action": "keep"},
        "internal_note": {"action": "drop"}
      }
    }
  ]
}
```

每张表逐字段声明动作：

| action | 含义 | 必填 |
| --- | --- | --- |
| `id` | 标识字段，按实体规则转假名 | `entity`、`normalize` |
| `ref` | 引用字段，按同一实体规则转假名 | `entity`、`normalize`、`ref_table`、`ref_field` |
| `keep` | 普通业务值，原样输出 | 无 |
| `drop` | 禁止输出，投影时删除 | 无 |

`normalize` 允许 `exact`、`strip`、`upper_ascii`（仅 ASCII 字符集）。
同一实体在所有表必须使用相同规范化规则与假名长度，否则配置校验失败。

引用字段可选 `nullable: true`：显式空值输出为空；未声明时缺失引用即失败。
表中允许出现策略未声明的列时，视为配置遗漏，整次交付失败。

## 键文件

键文件是调用者自备的本地私有 JSON 文件，**不进入仓库、不复制进输出**：

```json
{
  "algorithm": "HMAC-SHA256",
  "keys": {
    "v1": {"algorithm": "HMAC-SHA256", "secret": "base64:<32字节以上>"},
    "v2": {"algorithm": "HMAC-SHA256", "secret": "hex:<32字节以上>"}
  }
}
```

`secret` 必须显式带 `base64:`、`hex:` 或 `utf8:` 前缀，密钥不少于 32 字节。
POSIX 下若文件对组或其他用户可读（权限位含 0o077）则拒绝载入。测试用合成
密钥由 `keygen` 或 `generate_key_file` 临时生成，用后随临时目录清理。

## 完整性与失败语义

转换分为索引与投影两遍。以下情况收集为错误条目并使整次交付失败：

- 主键重复；标识或引用缺失；引用指向不存在的对象。
- 两个不同原值规范化后相等（歧义合并），例如 `v-001` 与 `V-001`。
- 同一实体出现截断假名碰撞，或出现未声明的数据列。
- 策略遗漏标识字段声明、引用目标不存在或实体规则不一致。

失败时**不写出任何假名表**，也不保留半成品清单；只在输出目录写
`errors.jsonl`，每行仅含 `code`、`table`、`field`、`row`、`entity`，不回显
业务原值或密钥。成功时删除错误日志与断点日志。

## 交付包与轮换

输出目录包含假名化表与 `manifest.json`。清单记录作用域、键版本、算法、
编码标签、策略摘要（各字段动作与实体规范化规则）、各表列结构、行数与摘要，
但不含原值对照表或任何密钥材料。

- 一次调用只允许一个键版本；不同版本写入各自独立目录。
- 已存在的完成清单不会被静默覆盖；旧版本目录内容保持不动。
- 轮换即用新版本再导出一份，两份包互不影响。

## 断点与清理边界

处理中输出目录保留 `.journal.json`，记录完整作用域、键版本、算法、策略摘要
与输入文件摘要。仅当显式 `--resume` 且作用域、策略、输入完全一致时可续跑；
跨合作方或跨窗口恢复会因作用域不匹配被拒绝，已完成的输出还会校验文件摘要。

| 文件 | 位置 | 生命周期 |
| --- | --- | --- |
| 键文件 | 调用者私有路径 | 库只读；不复制、不写入结果 |
| `.pending-*` | 输出目录 | 原子写入的临时文件，失败或成功后均删除 |
| `.journal.json` | 输出目录 | 运行中；成功后删除；失败时删除 |
| `errors.jsonl` | 输出目录（可用 `--error-log` 覆盖） | 仅失败生成，下次同目录运行开始时清除 |
| `manifest.json` 与表 | 输出目录 | 成功后保留，作为该键版本与作用域的独立副本 |

## 错误码

配置与作用域：`SCOPE_INVALID`、`POLICY_FORMAT`、`POLICY_TABLE_DUPLICATE`、
`POLICY_ACTION_INVALID`、`POLICY_ENTITY_MISSING`、`NORMALIZER_UNKNOWN`、
`POLICY_NORMALIZER_CONFLICT`、`POLICY_LENGTH_CONFLICT`、
`POLICY_PRIMARY_NOT_ID`、`POLICY_REF_TARGET_MISSING`、
`POLICY_REF_TARGET_NOT_ID`、`POLICY_REF_ENTITY_MISMATCH`、
`POLICY_SCOPE_INVALID`、`SCOPE_NOT_ALLOWED`、
`PSEUDONYM_LENGTH_INVALID`、`ID_TYPE`。

键文件：`KEY_FILE_MISSING`、`KEY_FILE_PERMISSIONS`、`KEY_FILE_FORMAT`、
`KEY_TOO_SHORT`、`KEY_FILE_EXISTS`、`KEY_VERSION_UNKNOWN`。

数据与交付：`ROW_NOT_OBJECT`、`ROW_FIELD_UNDECLARED`、`PRIMARY_DUPLICATE`、
`VALUE_MISSING`、`REF_MISSING`、`REF_DANGLING`、`NORMALIZATION_COLLISION`、
`PSEUDONYM_COLLISION`、`PSEUDONYM_SHAPE_INVALID`、`BUNDLE_FORMAT`、
`BUNDLE_TABLE_MISSING`、`BUNDLE_FILE_UNDECLARED`、`OUTPUT_FORMAT_UNSUPPORTED`、
`OUTPUT_WRITE_FAILED`、`JOURNAL_CORRUPT`、`JOURNAL_EXISTS_WITHOUT_RESUME`、
`JOURNAL_SCOPE_MISMATCH`、`JOURNAL_POLICY_CHANGED`、`JOURNAL_INPUT_CHANGED`、
`JOURNAL_OUTPUT_CORRUPT`、`JOURNAL_NOT_FOUND`、`PACKAGE_ALREADY_EXISTS`、
`TRANSFORM_FAILED`。

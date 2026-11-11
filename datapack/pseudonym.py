"""作用域假名化核心。

提供 HMAC-SHA256 作用域假名、策略校验与整表转换的纯计算逻辑，不直接读写
业务数据文件。作用域至少包含合作方、项目、窗口、实体类型与键版本五个维度，
配合有边界的长度前缀编码，保证同一作用域内相同实体稳定一致、不同作用域的
假名不可复用。

密钥只以字节形式存在于调用者载入的 Keyring 中，不写入配置副本、结果、进度
或异常文本。所有错误只携带错误码、字段路径与行号，绝不回显业务原值或密钥。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path

from .domain import framed, normalize as normalize_value
from .storage import read_json

ALGORITHM = "HMAC-SHA256"
ENCODING = "framed-utf8-u32be"
LABEL = "datapack.pseudonym/v1"
FULL_LENGTH = 64
MIN_LENGTH = 2
MIN_KEY_BYTES = 32
ACTIONS = ("id", "ref", "keep", "drop")
NORMALIZERS = ("exact", "strip", "upper_ascii")
SCOPE_KEYS = ("partner", "project", "window", "key_version")


class PseudonymError(Exception):
    """只携带错误码与定位信息的异常，任何字段都不允许是业务原值或密钥。"""

    def __init__(self, code, table=None, field=None, row=None, entity=None):
        self.code = code
        self.table = table
        self.field = field
        self.row = row
        self.entity = entity
        super().__init__(self.message())

    def entry(self):
        out = {"code": self.code}
        for key in ("table", "field", "row", "entity"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    def message(self):
        bits = [self.code]
        if self.table is not None:
            bits.append("table=" + str(self.table))
        if self.field is not None:
            bits.append("field=" + str(self.field))
        if self.row is not None:
            bits.append("row=" + str(self.row))
        if self.entity is not None:
            bits.append("entity=" + str(self.entity))
        return " ".join(bits)


class TransformFailure(PseudonymError):
    """一次转换中收集到的全部数据级错误，错误条目不含任何原值。"""

    def __init__(self, entries):
        self.entries = entries
        super().__init__("TRANSFORM_FAILED")

    def message(self):
        return "TRANSFORM_FAILED count=" + str(len(self.entries))


@dataclass(frozen=True)
class Scope:
    """共享合同作用域：合作方、项目、周窗口、键版本，实体维度在取假名时追加。"""

    partner: str
    project: str
    window: str
    key_version: str

    def __post_init__(self):
        for key in SCOPE_KEYS:
            value = getattr(self, key)
            if not isinstance(value, str) or not value:
                raise PseudonymError("SCOPE_INVALID", field=key)

    def as_dict(self):
        return {key: getattr(self, key) for key in SCOPE_KEYS}

    def for_entity(self, entity):
        if not isinstance(entity, str) or not entity:
            raise PseudonymError("SCOPE_INVALID", field="entity")
        return _EntityScope(self, entity)


@dataclass(frozen=True)
class _EntityScope:
    base: Scope
    entity: str

    def parts(self):
        return (
            self.base.partner,
            self.base.project,
            self.base.window,
            self.entity,
            self.base.key_version,
        )


def encode_message(entity_scope, normalized):
    """作用域与规范化原值的有边界编码：每段以 u32 大端长度前缀封 frame。"""
    if not isinstance(normalized, str):
        raise PseudonymError("ID_TYPE")
    return framed((LABEL, *entity_scope.parts(), normalized))


def derive_pseudonym(key, entity_scope, normalized, length=FULL_LENGTH):
    """标准 HMAC-SHA256 派生十六进制假名；截断长度须显式合法，碰撞由 Engine 阻断。"""
    if not isinstance(length, int) or not (MIN_LENGTH <= length <= FULL_LENGTH):
        raise PseudonymError("PSEUDONYM_LENGTH_INVALID", entity=entity_scope.entity)
    digest = hmac.new(key, encode_message(entity_scope, normalized), hashlib.sha256)
    return digest.hexdigest()[:length]


class Keyring:
    """从调用者提供的本地私有文件读取键版本与密钥字节，进程内不做任何落盘副本。"""

    def __init__(self, path):
        key_path = Path(path)
        if not key_path.is_file():
            raise PseudonymError("KEY_FILE_MISSING")
        if os.name == "posix" and (key_path.stat().st_mode & 0o077):
            raise PseudonymError("KEY_FILE_PERMISSIONS")
        try:
            raw = read_json(key_path)
        except (ValueError, OSError):
            raise PseudonymError("KEY_FILE_FORMAT") from None
        if not isinstance(raw, dict) or not isinstance(raw.get("keys"), dict):
            raise PseudonymError("KEY_FILE_FORMAT")
        keys = {}
        for version, item in raw["keys"].items():
            if not isinstance(version, str) or not version or not isinstance(item, dict):
                raise PseudonymError("KEY_FILE_FORMAT")
            secret = item.get("secret")
            algorithm = item.get("algorithm", ALGORITHM)
            if not isinstance(secret, str) or algorithm != ALGORITHM:
                raise PseudonymError("KEY_FILE_FORMAT", entity=version)
            secret_bytes = _decode_secret(secret, version)
            if len(secret_bytes) < MIN_KEY_BYTES:
                raise PseudonymError("KEY_TOO_SHORT", entity=version)
            keys[version] = secret_bytes
        if not keys:
            raise PseudonymError("KEY_FILE_FORMAT")
        self._keys = keys

    def key_for(self, version):
        try:
            return self._keys[version]
        except KeyError:
            raise PseudonymError("KEY_VERSION_UNKNOWN", field=version) from None

    def versions(self):
        return sorted(self._keys)

    def close(self):
        self._keys.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False


def _decode_secret(secret, version):
    for prefix, decoder in (
        ("base64:", lambda body: base64.b64decode(body, validate=True)),
        ("hex:", lambda body: bytes.fromhex(body)),
        ("utf8:", lambda body: body.encode("utf-8")),
    ):
        if secret.startswith(prefix):
            try:
                return decoder(secret[len(prefix):])
            except (ValueError, TypeError):
                raise PseudonymError("KEY_FILE_FORMAT", entity=version) from None
    raise PseudonymError("KEY_FILE_FORMAT", entity=version)


def validate_policy(raw):
    """校验策略并返回规范化结构；配置级错误立即失败，不允许带歧义交付。

    策略可为表数组（不再声明允许作用域），或含 `scopes` 与 `tables` 的对象。
    `scopes` 是共享合同白名单，每项给出合作方、项目、周窗口与键版本。
    """
    if isinstance(raw, dict) and "tables" in raw:
        scopes_raw = raw.get("scopes")
        tables_raw = raw["tables"]
    elif isinstance(raw, list):
        scopes_raw = None
        tables_raw = raw
    else:
        raise PseudonymError("POLICY_FORMAT")
    if not isinstance(tables_raw, list) or not tables_raw:
        raise PseudonymError("POLICY_FORMAT")
    scopes = []
    if scopes_raw is not None:
        if not isinstance(scopes_raw, list) or not scopes_raw:
            raise PseudonymError("POLICY_SCOPE_INVALID")
        for item in scopes_raw:
            if not isinstance(item, dict):
                raise PseudonymError("POLICY_SCOPE_INVALID")
            clean_scope = {}
            for key in SCOPE_KEYS:
                value = item.get(key)
                if not isinstance(value, str) or not value:
                    raise PseudonymError("POLICY_SCOPE_INVALID", field=key)
                clean_scope[key] = value
            scopes.append(clean_scope)
    tables = {}
    order = []
    entity_rules = {}
    entity_lengths = {}
    for spec in tables_raw:
        if not isinstance(spec, dict) or not isinstance(spec.get("table"), str) or not spec["table"]:
            raise PseudonymError("POLICY_FORMAT")
        name = spec["table"]
        if name in tables:
            raise PseudonymError("POLICY_TABLE_DUPLICATE", table=name)
        primary = spec.get("primary")
        fields = spec.get("fields")
        if not isinstance(primary, str) or not isinstance(fields, dict) or not fields:
            raise PseudonymError("POLICY_FORMAT", table=name)
        length = spec.get("pseudonym_length", FULL_LENGTH)
        if not isinstance(length, int) or not (MIN_LENGTH <= length <= FULL_LENGTH):
            raise PseudonymError("PSEUDONYM_LENGTH_INVALID", table=name)
        clean_fields = {}
        for field_name, field_spec in fields.items():
            if not isinstance(field_name, str) or not isinstance(field_spec, dict):
                raise PseudonymError("POLICY_FORMAT", table=name)
            action = field_spec.get("action")
            if action not in ACTIONS:
                raise PseudonymError("POLICY_ACTION_INVALID", table=name, field=field_name)
            clean = {"action": action}
            if action in ("id", "ref"):
                entity = field_spec.get("entity")
                normalizer = field_spec.get("normalize")
                if not isinstance(entity, str) or not entity:
                    raise PseudonymError("POLICY_ENTITY_MISSING", table=name, field=field_name)
                if normalizer not in NORMALIZERS:
                    raise PseudonymError("NORMALIZER_UNKNOWN", table=name, field=field_name)
                clean["entity"] = entity
                clean["normalize"] = normalizer
                prev = entity_rules.get(entity)
                if prev is not None and prev != normalizer:
                    raise PseudonymError(
                        "POLICY_NORMALIZER_CONFLICT", table=name, field=field_name, entity=entity
                    )
                entity_rules[entity] = normalizer
                if entity in entity_lengths and entity_lengths[entity] != length:
                    raise PseudonymError("POLICY_LENGTH_CONFLICT", table=name, entity=entity)
                entity_lengths[entity] = length
            if action == "ref":
                ref_table = field_spec.get("ref_table")
                ref_field = field_spec.get("ref_field")
                if not isinstance(ref_table, str) or not isinstance(ref_field, str):
                    raise PseudonymError("POLICY_REF_TARGET_MISSING", table=name, field=field_name)
                clean["ref_table"] = ref_table
                clean["ref_field"] = ref_field
                nullable = field_spec.get("nullable", False)
                if not isinstance(nullable, bool):
                    raise PseudonymError("POLICY_FORMAT", table=name, field=field_name)
                clean["nullable"] = nullable
            clean_fields[field_name] = clean
        if primary not in clean_fields or clean_fields[primary]["action"] != "id":
            raise PseudonymError("POLICY_PRIMARY_NOT_ID", table=name, field=primary)
        tables[name] = {"name": name, "primary": primary, "length": length, "fields": clean_fields}
        order.append(name)
    for name, table in tables.items():
        for field_name, field_spec in table["fields"].items():
            if field_spec["action"] != "ref":
                continue
            target = tables.get(field_spec["ref_table"])
            if target is None or field_spec["ref_field"] not in target["fields"]:
                raise PseudonymError("POLICY_REF_TARGET_MISSING", table=name, field=field_name)
            target_spec = target["fields"][field_spec["ref_field"]]
            if target_spec["action"] != "id":
                raise PseudonymError("POLICY_REF_TARGET_NOT_ID", table=name, field=field_name)
            if target_spec["entity"] != field_spec["entity"]:
                raise PseudonymError("POLICY_REF_ENTITY_MISMATCH", table=name, field=field_name)
    return {"tables": tables, "order": order, "scopes": scopes if scopes_raw is not None else None}


def scope_allowed(policy, scope):
    """策略声明了白名单时，只有四维完全一致的共享合同才允许导出。"""
    scopes = policy.get("scopes")
    if scopes is None:
        return True
    return any(scope.as_dict() == item for item in scopes)


@dataclass
class _EntityState:
    normalizer: str
    length: int
    first_raw: dict = field(default_factory=dict)
    pseudonyms: dict = field(default_factory=dict)
    owners: dict = field(default_factory=dict)
    identifiers: set = field(default_factory=set)


class Engine:
    """按策略把多张表转换为作用域假名表，集中执行完整性与碰撞阻断。"""

    def __init__(self, keyring, scope, policy, derive=derive_pseudonym):
        self.keyring = keyring
        self.scope = scope
        self.policy = policy
        self._derive = derive
        self.errors = []
        self._reported = set()
        self.states = {}
        for name, table in policy["tables"].items():
            for field_spec in table["fields"].values():
                if field_spec["action"] in ("id", "ref"):
                    entity = field_spec["entity"]
                    self.states.setdefault(
                        entity,
                        _EntityState(normalizer=field_spec["normalize"], length=table["length"]),
                    )

    def run(self, tables):
        """tables 为 {表名: 行列表}；成功返回 {表名: 输出行列表}，失败抛 TransformFailure。"""
        for name in self.policy["order"]:
            if name not in tables:
                raise PseudonymError("BUNDLE_TABLE_MISSING", table=name)
        for name in self.policy["order"]:
            self._index_identifiers(name, tables[name])
        outputs = {name: self._project_table(name, tables[name]) for name in self.policy["order"]}
        if self.errors:
            entries = sorted(
                (entry.entry() if isinstance(entry, PseudonymError) else entry for entry in self.errors),
                key=lambda item: (
                    str(item.get("table", "")),
                    item.get("row", -1) if isinstance(item.get("row"), int) else -1,
                    str(item.get("field", "")),
                    str(item.get("code", "")),
                ),
            )
            raise TransformFailure(entries)
        return outputs

    def _fail(self, code, table, field_name, row, entity=None):
        marker = (code, table, field_name, row, entity)
        if marker in self._reported:
            return
        self._reported.add(marker)
        self.errors.append(PseudonymError(code, table=table, field=field_name, row=row, entity=entity))

    def _index_identifiers(self, table_name, rows):
        table = self.policy["tables"][table_name]
        seen_primary = set()
        for row_no, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                self._fail("ROW_NOT_OBJECT", table_name, None, row_no)
                continue
            for column in row:
                if column not in table["fields"]:
                    self._fail("ROW_FIELD_UNDECLARED", table_name, column, row_no)
            primary = table["primary"]
            primary_spec = table["fields"][primary]
            normalized = self._normalize(table_name, primary, row_no, primary_spec, row.get(primary))
            if normalized is None:
                continue
            if normalized in seen_primary:
                self._fail("PRIMARY_DUPLICATE", table_name, primary, row_no, primary_spec["entity"])
            seen_primary.add(normalized)
            for field_name, field_spec in table["fields"].items():
                if field_spec["action"] == "id":
                    self._register_identifier(table_name, field_name, row_no, field_spec, row.get(field_name))

    def _register_identifier(self, table_name, field_name, row_no, field_spec, raw_value):
        entity = field_spec["entity"]
        state = self.states[entity]
        normalized = self._normalize(table_name, field_name, row_no, field_spec, raw_value)
        if normalized is None:
            return
        if normalized in state.first_raw:
            previous_raw, _ = state.first_raw[normalized]
            if previous_raw != raw_value:
                self._fail("NORMALIZATION_COLLISION", table_name, field_name, row_no, entity)
                return
        else:
            state.first_raw[normalized] = (raw_value, (table_name, field_name, row_no))
        state.identifiers.add(normalized)
        if normalized not in state.pseudonyms:
            entity_scope = self.scope.for_entity(entity)
            try:
                pseudonym = self._derive(
                    self.keyring.key_for(self.scope.key_version),
                    entity_scope,
                    normalized,
                    state.length,
                )
            except PseudonymError as exc:
                self._fail(exc.code, table_name, field_name, row_no, entity)
                return
            if not isinstance(pseudonym, str) or len(pseudonym) != state.length:
                self._fail("PSEUDONYM_SHAPE_INVALID", table_name, field_name, row_no, entity)
                return
            if pseudonym in state.owners and state.owners[pseudonym][0] != normalized:
                self._fail("PSEUDONYM_COLLISION", table_name, field_name, row_no, entity)
                return
            state.owners[pseudonym] = (normalized, (table_name, field_name, row_no))
            state.pseudonyms[normalized] = pseudonym

    def _project_table(self, table_name, rows):
        table = self.policy["tables"][table_name]
        columns = [name for name, spec in table["fields"].items() if spec["action"] != "drop"]
        outputs = []
        for row_no, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                continue
            out = {}
            for field_name in columns:
                field_spec = table["fields"][field_name]
                action = field_spec["action"]
                if action == "id":
                    out[field_name] = self._pseudonym_for(
                        table_name, field_name, row_no, field_spec, row.get(field_name)
                    )
                elif action == "ref":
                    out[field_name] = self._reference_value(
                        table_name, field_name, row_no, field_spec, row.get(field_name)
                    )
                else:
                    out[field_name] = row.get(field_name)
            outputs.append(out)
        return outputs

    def _reference_value(self, table_name, field_name, row_no, field_spec, raw_value):
        if raw_value is None:
            if field_spec.get("nullable"):
                return None
            self._fail("REF_MISSING", table_name, field_name, row_no, field_spec["entity"])
            return None
        normalized = self._normalize(table_name, field_name, row_no, field_spec, raw_value)
        if normalized is None:
            return None
        state = self.states[field_spec["entity"]]
        if normalized not in state.identifiers:
            self._fail("REF_DANGLING", table_name, field_name, row_no, field_spec["entity"])
            return None
        return state.pseudonyms.get(normalized)

    def _pseudonym_for(self, table_name, field_name, row_no, field_spec, raw_value):
        state = self.states[field_spec["entity"]]
        normalized = self._normalize(table_name, field_name, row_no, field_spec, raw_value)
        if normalized is None:
            return None
        return state.pseudonyms.get(normalized)

    def _normalize(self, table_name, field_name, row_no, field_spec, raw_value):
        if raw_value is None:
            self._fail("VALUE_MISSING", table_name, field_name, row_no, field_spec.get("entity"))
            return None
        try:
            return normalize_value(raw_value, field_spec["normalize"])
        except ValueError as exc:
            self._fail(str(exc), table_name, field_name, row_no, field_spec.get("entity"))
            return None

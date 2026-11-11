"""假名化导出编排：数据包加载、断点日志、原子输出、清单与错误日志。

清理边界：
- output 目录只放假名化结果表、manifest.json；成功后断点日志删除。
- errors.jsonl 只在失败时生成，仅含错误码、字段路径、行号；成功时不保留。
- 所有临时文件经 storage.atomic_write 的 .pending-* 机制，写入失败即删除。
- 键文件保持在调用者指定的私有路径，本模块不复制、不缓存路径之外的任何键材料。
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .pseudonym import (
    ALGORITHM,
    ENCODING,
    LABEL,
    Engine,
    Keyring,
    PseudonymError,
    TransformFailure,
    scope_allowed,
    validate_policy,
)
from .records import load_rows
from .storage import atomic_write, canonical, confined, read_json, save_json

JOURNAL_NAME = ".journal.json"
MANIFEST_NAME = "manifest.json"
ERROR_LOG_NAME = "errors.jsonl"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def generate_key_file(path, versions, force=False):
    """为测试或初始化生成键文件；默认 0600，拒绝静默覆盖。运行密钥应由调用者自备。"""
    import base64

    key_path = Path(path)
    if key_path.exists() and not force:
        raise PseudonymError("KEY_FILE_EXISTS")
    if isinstance(versions, str):
        versions = [versions]
    if not versions:
        raise PseudonymError("KEY_FILE_FORMAT")
    keys = {}
    for version in versions:
        if not isinstance(version, str) or not version:
            raise PseudonymError("KEY_FILE_FORMAT")
        if version in keys:
            raise PseudonymError("KEY_FILE_FORMAT", entity=version)
        keys[version] = {
            "algorithm": ALGORITHM,
            "secret": "base64:" + base64.b64encode(os.urandom(32)).decode("ascii"),
        }
    key_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(key_path, {"algorithm": ALGORITHM, "keys": keys})
    os.chmod(key_path, 0o600)
    return {"path": str(key_path), "versions": sorted(keys), "mode": "0600"}


def load_bundle(bundle_dir):
    """读取 bundle.json 并按其中声明加载每张表，路径限制在数据目录内。"""
    root = Path(bundle_dir)
    config = read_json(root / "bundle.json")
    if not isinstance(config, dict) or not isinstance(config.get("files"), list):
        raise PseudonymError("BUNDLE_FORMAT")
    tables = {}
    inputs = []
    for item in config["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise PseudonymError("BUNDLE_FORMAT")
        if item.get("config"):
            continue
        table_name = item.get("table") or Path(item["path"]).stem
        if not isinstance(table_name, str) or table_name in tables:
            raise PseudonymError("BUNDLE_FORMAT", table=table_name)
        source = confined(root, item["path"])
        rows = load_rows(source)
        tables[table_name] = rows
        inputs.append(
            {
                "table": table_name,
                "source": item["path"],
                "sha256": sha256_file(source),
                "rows": len(rows),
            }
        )
    return inputs, tables


def _write_table(path, rows, columns, suffix):
    if suffix == ".json":
        data = canonical(rows) + b"\n"
    elif suffix == ".jsonl":
        buffer = io.StringIO()
        for row in rows:
            buffer.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            buffer.write("\n")
        data = buffer.getvalue().encode("utf-8")
    elif suffix == ".csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="raise")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: ("" if row.get(name) is None else row.get(name)) for name in columns})
        data = buffer.getvalue().encode("utf-8")
    else:
        raise PseudonymError("OUTPUT_FORMAT_UNSUPPORTED")
    try:
        atomic_write(path, data)
    except (TypeError, ValueError):
        raise PseudonymError("OUTPUT_WRITE_FAILED") from None
    return sha256_file(path)


def _read_journal(path):
    try:
        return read_json(path)
    except (ValueError, OSError):
        raise PseudonymError("JOURNAL_CORRUPT") from None


def _write_error_log(path, entries):
    lines = b"".join(canonical(entry) + b"\n" for entry in entries)
    atomic_write(path, lines)


def _policy_summary(policy):
    summary = {}
    entities = {}
    for name in policy["order"]:
        table = policy["tables"][name]
        fields = {}
        for field_name, spec in table["fields"].items():
            fields[field_name] = {key: value for key, value in spec.items()}
        summary[name] = {"primary": table["primary"], "fields": fields}
        for spec in table["fields"].values():
            if spec["action"] in ("id", "ref"):
                entities[spec["entity"]] = {
                    "normalize": spec["normalize"],
                    "pseudonym_length": table["length"],
                }
    return summary, [
        {"entity": entity, **detail} for entity, detail in sorted(entities.items())
    ]


def export_package(bundle_dir, policy_path, key_path, scope, out_dir, resume=False, error_log=None):
    """执行一次完整交付；成功返回清单摘要，失败写错误日志并抛 TransformFailure。

    一次调用只允许一个作用域与一个键版本；断点日志绑定完整作用域，跨作用域
    恢复直接拒绝。输出目录中已有完成清单时不会被静默覆盖。
    """
    bundle_dir = Path(bundle_dir)
    out_dir = Path(out_dir)
    journal_path = out_dir / JOURNAL_NAME
    manifest_path = out_dir / MANIFEST_NAME
    log_path = Path(error_log) if error_log else out_dir / ERROR_LOG_NAME

    policy_bytes = Path(policy_path).read_bytes()
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
    policy = validate_policy(read_json(Path(policy_path)))
    if not scope_allowed(policy, scope):
        raise PseudonymError("SCOPE_NOT_ALLOWED")
    inputs, source_tables = load_bundle(bundle_dir)
    for table in policy["order"]:
        if table not in source_tables:
            raise PseudonymError("BUNDLE_TABLE_MISSING", table=table)
    for item in inputs:
        if item["table"] not in policy["tables"]:
            raise PseudonymError("BUNDLE_FILE_UNDECLARED", table=item["table"])
        if Path(item["source"]).suffix not in (".json", ".jsonl", ".csv"):
            raise PseudonymError("OUTPUT_FORMAT_UNSUPPORTED", table=item["table"])

    out_dir.mkdir(parents=True, exist_ok=True)
    if manifest_path.exists():
        if not resume:
            raise PseudonymError("PACKAGE_ALREADY_EXISTS")
        manifest = read_json(manifest_path)
        if manifest.get("scope") != scope.as_dict() or manifest.get("policy", {}).get("digest") != policy_digest:
            raise PseudonymError("JOURNAL_SCOPE_MISMATCH")

    journal = None
    if journal_path.exists():
        if not resume:
            raise PseudonymError("JOURNAL_EXISTS_WITHOUT_RESUME")
        journal = _read_journal(journal_path)
        if journal.get("scope") != scope.as_dict():
            raise PseudonymError("JOURNAL_SCOPE_MISMATCH")
        if journal.get("policy_digest") != policy_digest:
            raise PseudonymError("JOURNAL_POLICY_CHANGED")
        if journal.get("inputs") != {
            name: {"source": detail["source"], "sha256": detail["sha256"], "rows": detail["rows"]}
            for name, detail in ((item["table"], item) for item in inputs)
        }:
            raise PseudonymError("JOURNAL_INPUT_CHANGED")
    elif resume:
        raise PseudonymError("JOURNAL_NOT_FOUND")
    else:
        stale_log = out_dir / ERROR_LOG_NAME
        if stale_log.exists():
            stale_log.unlink()
        journal = {
            "scope": scope.as_dict(),
            "key_version": scope.key_version,
            "algorithm": ALGORITHM,
            "encoding": ENCODING,
            "frame_label": LABEL,
            "policy_digest": policy_digest,
            "inputs": {
                item["table"]: {
                    "source": item["source"],
                    "sha256": item["sha256"],
                    "rows": item["rows"],
                }
                for item in inputs
            },
            "completed": {},
        }
        save_json(journal_path, journal)

    try:
        with Keyring(key_path) as keyring:
            engine = Engine(keyring, scope, policy)
            outputs = engine.run(source_tables)
    except TransformFailure as failure:
        for name in list(journal.get("completed", {})):
            stale = out_dir / journal["completed"][name]["output"]
            if stale.exists():
                stale.unlink()
        if journal_path.exists():
            journal_path.unlink()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        _write_error_log(log_path, failure.entries)
        raise
    except PseudonymError:
        if journal_path.exists() and not resume:
            journal_path.unlink()
        raise

    completed = dict(journal.get("completed", {}))
    table_manifests = []
    for item in inputs:
        name = item["table"]
        table = policy["tables"][name]
        rows = outputs[name]
        columns = [
            field_name
            for field_name, spec in table["fields"].items()
            if spec["action"] != "drop"
        ]
        output_name = item["source"]
        output_path = confined(out_dir, output_name)
        done = completed.get(name)
        if done and done.get("output") == output_name and output_path.exists():
            if sha256_file(output_path) != done.get("sha256"):
                raise PseudonymError("JOURNAL_OUTPUT_CORRUPT", table=name)
        else:
            digest = _write_table(output_path, rows, columns, Path(output_name).suffix)
            completed[name] = {"output": output_name, "sha256": digest, "rows": len(rows)}
            journal["completed"] = completed
            save_json(journal_path, journal)
        table_manifests.append(
            {
                "table": name,
                "source": item["source"],
                "output": output_name,
                "rows": len(rows),
                "columns": columns,
                "sha256": completed[name]["sha256"],
                "pseudonym_length": table["length"],
            }
        )

    summary, entities = _policy_summary(policy)
    manifest = {
        "package": uuid.uuid4().hex,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "algorithm": ALGORITHM,
        "encoding": ENCODING,
        "frame_label": LABEL,
        "scope": scope.as_dict(),
        "key_version": scope.key_version,
        "policy": {"digest": policy_digest, "tables": summary},
        "entities": entities,
        "tables": table_manifests,
    }
    save_json(manifest_path, manifest)
    journal_path.unlink()
    return manifest

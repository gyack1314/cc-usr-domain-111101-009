import argparse
import json
import sys
from pathlib import Path
from .pipeline import ERROR_LOG_NAME, export_package, generate_key_file
from .pseudonym import PseudonymError, Scope, TransformFailure
from .records import inspect_bundle
from .storage import RevisionStore


def _build_parser():
    parser = argparse.ArgumentParser(description="作用域假名化数据包工具")
    commands = parser.add_subparsers(dest="command", required=True)

    inspect_parser = commands.add_parser("inspect", help="检查数据包可读性与摘要")
    inspect_parser.add_argument("bundle", type=Path)

    catalog_parser = commands.add_parser("catalog", help="读取修订目录最新版本")
    catalog_parser.add_argument("database", type=Path)
    catalog_parser.add_argument("stream")

    keygen_parser = commands.add_parser("keygen", help="为测试生成临时键文件（0600）")
    keygen_parser.add_argument("--key-file", type=Path, required=True)
    keygen_parser.add_argument("--version", action="append", dest="versions", required=True)
    keygen_parser.add_argument("--force", action="store_true")

    export_parser = commands.add_parser("export", help="按策略与作用域导出假名化数据包")
    export_parser.add_argument("--bundle", type=Path, required=True)
    export_parser.add_argument("--policy", type=Path, required=True)
    export_parser.add_argument("--key-file", type=Path, required=True)
    export_parser.add_argument("--partner", required=True)
    export_parser.add_argument("--project", required=True)
    export_parser.add_argument("--window", required=True)
    export_parser.add_argument("--key-version", required=True)
    export_parser.add_argument("--out", type=Path, required=True)
    export_parser.add_argument("--resume", action="store_true")
    export_parser.add_argument("--error-log", type=Path, default=None)
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            value = inspect_bundle(args.bundle)
        elif args.command == "catalog":
            value = RevisionStore(args.database).latest(args.stream)
        elif args.command == "keygen":
            value = generate_key_file(args.key_file, args.versions, force=args.force)
        else:
            scope = Scope(args.partner, args.project, args.window, args.key_version)
            value = export_package(
                args.bundle,
                args.policy,
                args.key_file,
                scope,
                args.out,
                resume=args.resume,
                error_log=args.error_log,
            )
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0
    except TransformFailure as failure:
        log_path = args.error_log if args.error_log else (args.out / ERROR_LOG_NAME)
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_count": len(failure.entries),
                    "error_log": str(log_path),
                    "codes": sorted({entry["code"] for entry in failure.entries}),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2
    except (PseudonymError, ValueError, KeyError, OSError) as exc:
        if isinstance(exc, PseudonymError):
            print(json.dumps({"status": "failed", "error": exc.message()}, ensure_ascii=False), file=sys.stderr)
        else:
            print("输入资料或目录无效，请检查路径及字段说明", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

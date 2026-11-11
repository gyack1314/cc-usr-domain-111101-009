# 多方日志共享的作用域假名与键轮换数据包

共享表字段策略、作用域 HMAC-SHA256 假名化与关系完整性检查工具，提供严格字段路径和实体规范化原语。数据文件位于samples，字段和边界见docs/domain.md，假名化与轮换设计见docs/pseudonym.md，持久目录接口见docs/storage.md。

## 本地运行

Python 3.11以上，仅依赖标准库，无需真实账号或外部数据服务。

```bash
python -m datapack.cli inspect samples
python -m unittest discover -s tests -v
python -m compileall -q datapack tests
```

第一条命令检查已有资料，第二条运行读取、内容存储、领域原语、键环与作用域假名化端到端检查，第三条构建Python字节码。

## 作用域导出

键文件由调用者自备，库只读取、不复制到结果。测试或本地演示可用`keygen`临时生成：

```bash
python -m datapack.cli keygen --key-file private/keys.json --version v1
python -m datapack.cli export \
  --bundle samples --policy samples/policies.json \
  --key-file private/keys.json \
  --partner P1 --project traffic-data --window 2026-W45 --key-version v1 \
  --out output/P1-W45-v1
```

输出目录含假名化表与manifest.json，记录作用域、键版本、策略摘要与列结构，不含原值对照表。成功时无错误日志；失败时只写errors.jsonl（错误码、字段路径、行号），且不产生任何假名表。轮换时用新`--key-version`导出到独立目录，旧目录保持不动。断点续跑需显式`--resume`，跨作用域恢复会被拒绝。详见docs/pseudonym.md。


## 容器

```bash
docker build -t local-datapack .
docker run --rm --network none local-datapack
docker run --rm --network none local-datapack python -m unittest discover -s tests -v
```

应用没有必须常驻的服务，入口和库可在同一容器离线运行。state和output是本地工作目录，已排除出Git。样本文件只读，修订目录使用独立SQLite文件，旧版本可继续查询。

## 目录

datapack/storage.py提供摘要、原子文件与修订目录；datapack/records.py提供文件读取及重复主键分类；datapack/domain.py提供当前领域原语；datapack/pseudonym.py提供作用域假名、键环、策略校验与转换引擎；datapack/pipeline.py提供导出编排、断点与清理；tests验证这些行为。数据加工结果不由资料检查命令自动生成。

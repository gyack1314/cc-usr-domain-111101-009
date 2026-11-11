# 数据约定

策略中标识字段以entity和normalize声明，引用字段以ref_table和ref_field声明，普通值明确keep，禁止字段drop。所有输入字段必须被声明，忽略未声明字段不是合规投影。normalize仅允许exact、strip和upper_ascii。键文件必须由调用者生成，样本不保存生产密钥。

策略文件可以是含scopes与tables的对象（样本格式），scopes逐项列出允许的合作方、项目、周窗口与键版本作为共享合同白名单；也可以是纯tables数组，此时不做白名单限制。bundle.json中`config: true`的文件（如policies.json）是策略配置，不作为业务表导出；其余文件按文件主干名与策略表名对应。作用域导出的派生方式、失败语义、轮换与断点边界见pseudonym.md。同一作用域内标识与引用使用同一实体规则转换，因此主外键在输出中仍可连接。

样本为合成资料，包含正常、缺失、冲突等记录；这些现象用于保留业务数据原貌，读取成功不代表领域结果有效。所有计算原语位于datapack/domain.py；调用者负责组合、约束和最终验证。

# 数据约定

策略中标识字段以entity和normalize声明，引用字段以ref_table和ref_field声明，普通值明确keep，禁止字段drop。所有输入字段必须被声明，忽略未声明字段不是合规投影。normalize仅允许exact、strip和upper_ascii。键文件必须由调用者生成，样本不保存生产密钥。

样本为合成资料，包含正常、缺失、冲突等记录；这些现象用于保留业务数据原貌，读取成功不代表领域结果有效。所有计算原语位于datapack/domain.py；调用者负责组合、约束和最终验证。

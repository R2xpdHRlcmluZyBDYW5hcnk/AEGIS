# 事件搜索语言选型

## 核查依据

查询日期：2026-11-04，MCP Search Service。查询前检查已有狩猎字段、LLM 检索、引擎及依赖维护记录；既有记录没有覆盖第三方查询语言。查询条件为 DQL / KQL 的官方语法与解析实现、Lucene 查询语法、Sigma 规范、CEL 嵌入方式及 Python SQL 解析器。正文来源与结果：

| 来源 | 查询结果 | 项目适用性 |
| --- | --- | --- |
| [OpenSearch DQL](https://docs.opensearch.org/latest/dashboards/dql/) | 字段过滤、布尔组合、范围及通配符；字段的分析方式决定匹配行为 | 适合事件检索框的交互语法 |
| [DQL 上游语法](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/main/src/plugins/data/common/opensearch_query/kuery/ast/kuery.peg)与 [AST 接口](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/main/src/plugins/data/common/opensearch_query/kuery/ast/ast.ts) | 有 PEG 语法和 JavaScript 解析入口，现有输出目标为 OpenSearch 查询 | 可复用解析实现；没有开箱即用的 Python / SQLite 执行器 |
| [Kibana KQL](https://www.elastic.co/docs/reference/query-languages/kql) | 过滤语法，包括字段分组、比较、存在性及转义；与 Kusto Query Language 不是同一种语言 | 可作为语法对照；不能只改名称就宣称完整兼容 |
| [OpenSearch Lucene 查询](https://docs.opensearch.org/latest/query-dsl/full-text/query-string/) | 语法严格，含范围、通配符等；官方提示普通搜索框需考虑语法错误处理 | 适合熟悉该语法的高级用户，仍需字段语义与 SQLite 适配 |
| [Luqum](https://github.com/jurismarches/luqum) | Python Lucene 查询解析与 AST / Elasticsearch 转换 | 是现成解析器，但不是 Apache Lucene 执行引擎，也不是 SQLite 后端 |
| [Sigma 规范](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) | YAML 日志检测规则，包含日志源、选择条件和规则元数据 | 适合可保存、可共享的检测规则，不宜代替单行搜索框 |
| [CEL](https://cel.dev/overview/cel-overview) | 可嵌入、可检查的表达式语言，编译为 AST 后求值 | 可作条件表达式；逐条求值不能替代数据库索引查询 |
| [SQLGlot](https://github.com/tobymao/sqlglot) | Python SQL 解析与转换，支持 SQLite 方言 | 若采用 SQL 条件语法，是可复用的后端解析组件 |
| [kql-parser](https://github.com/Aloshi/kql-parser) | 提供 Python KQL 解析；README 仍列出关键字大小写及测试不足 | 本次不选作默认解析依赖 |

MCP 无法读取若干源码目录，补充使用官方 GitHub contents API 定位真实路径及 commits API 核查维护活动。2026-11-04 12:58 UTC 查得 OpenSearch Dashboards 与 SQLGlot 最近提交均在当日；Luqum 最近提交为 2026-03-30，kql-parser 为 2025-01-21。提交时间只证明该次查询可见的仓库活动，不代表兼容性、质量或性能测试结果。

## 推荐边界

推荐以 DQL 为事件搜索的目标语法，保留 SQLite 作为存储与执行后端。现有解析器混用了隐式 AND、Lucene 风格否定和自定义的冒号内数值比较；它不是完整的 DQL、KQL 或 Lucene 实现。

替换时应复用固定版本的上游语法与解析实现，明确输入、校验后的 AST、字段目录及参数化 SQL 编译器的边界。前端传来的 AST 也必须经过服务端的字段、类型、节点种类、深度和长度验证。不要部署 OpenSearch 集群来解决搜索框语法，也不要将 JavaScript 解析器误称为 Python 即插即用组件。

必须统一字符串精确匹配与包含匹配、大小写、NULL / 空字符串、IP / CIDR、日期、精确整数、通配符及 NOT 语义。现有检索链接和保存条件需要显式迁移，不能悄悄改变旧语句的结果。若不引入 JavaScript 服务端运行时，应先验证可复用的服务端解析方案；不能只在浏览器校验文本后让后端相信任意 SQL。

推荐的交互包括字段和值补全、错误位置与修正示例、条件构建器，以及可切换查看的规范化查询。统计和排序由已有界面管理。LLM 继续使用受限的结构化条件，后端负责校验与生成可展示语句；自然语言说明不进入执行器。

采用前的验证应覆盖与现有查询结果的对照、错误转义、同名字段、缺失字段、IPv6、CIDR、64 位整数、分页与取消，以及目标设备资源预算。本文是选型依据，不表示搜索语言已替换或已完成性能验收。

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

## 当前实现

事件搜索采用 Lucene 查询语法，由 Luqum 解析，SQLite 执行。服务端验证字段、值类型、AST 节点与复杂度，再编译为固定表达式和绑定参数。没有 OpenSearch、JavaScript 后端、任意 SQL、脚本或命令执行入口。LLM 自主拟定元数据查询，后端校验语法、字段、复杂度与参数化执行，限制附近时间和运行时长，默认查找其他会话；不强制命中当前 IOC 或告警。无效计划不执行，也不替换为固定查询。

```text
type:(http OR tls) AND NOT action:blocked
status:[400 TO 499]
status:{400 TO 500}
src:"2001:db8::/64"
session_id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0000000000000001"
sni:*.example.test
appid_service:HTTPS AND type:session
session_event:(start OR end)
```

相邻条件默认 AND。逻辑连接词 AND / OR / NOT 必须大写；条件之间的小写连接词会提示语法错误，若检索这些文字须使用双引号。双引号与反斜杠转义保留文字，带冒号、空格的值须加双引号；引号内的星号、问号按文字匹配。未加引号的 `*`、`?` 用作通配符。字符串默认包含匹配，大小写由界面控制；会话 ID 与原生 UID 按原文精确匹配，IP / CIDR 按地址语义匹配。数值支持闭区间 `[]`、开区间 `{}`、无界 `*` 和比较条件。`field:*` 检查字段存在性；缺失值、空字符串及 NOT 与服务端谓词语义一致。

不提供相关度评分、模糊匹配、正则表达式、boost 或查询脚本。不支持的节点、未知字段、无效类型和语法错误直接返回错误。输入上限 8192 字符，AST 上限 1024 节点，嵌套上限 20 层；长布尔列表规范化为平衡谓词，避免递归栈耗尽。前端提供字段及枚举值补全、可点击的合法示例和查询错误提示。

SQL 中的列名与运算符来自后端白名单，所有搜索值使用占位参数；检索词不会拼接到 SQL、Shell 或引擎控制命令。界面按文本渲染事件与应用名称。模型看不到数据库、文件系统或系统命令；模型建议规则还须经候选约束、规则校验和明确添加操作。

## Python 后端的解析器选择

2026-11-04 追加核查。查询前复用上述 DQL / Lucene / Python 适配记录，补查 Luqum 的官方 README、parser.py、thread.py 以及 PyPI 发行元数据。MCP Search Service 来源：[Luqum](https://github.com/jurismarches/luqum)、[解析入口](https://github.com/jurismarches/luqum/blob/master/luqum/parser.py)、[PyPI](https://pypi.org/project/luqum/)。MCP 未能读取部分目录，补充通过官方 GitHub tree API 定位文件，并通过 PyPI JSON API 取得 wheel URL、SHA-256 和依赖。

核查结果：Luqum 1.0.0 是当前发布的稳定版本，依赖 PLY 3.11；没有 LTS 发行线。解析器提供 Lucene 查询树，支持范围、字段分组与开区间比较。默认全局解析器不保证线程安全，应使用 luqum.thread.parse。该组件不提供 SQLite 执行器，必须由服务端验证 AST 并映射固定字段和参数化 SQL。

考虑当前 Python + SQLite 的执行环境，实施选择为 Lucene 查询语法与 Luqum，避免为解析增加常驻 JavaScript 或 OpenSearch 服务。依赖版本、官方 wheel 与校验值由 build_tools/python-sources.json 固定；构建时下载到临时目录、预生成 PLY 表并生成可只读导入的发行包，不在运行时下载依赖或写入解析缓存。第三方代码不保存到源码仓库。

实现期间验证标准范围、字段分组、转义、IPv6、缺失字段、精确整数、并发、复杂度上限及 SQL 参数化。字段帮助与检索链接统一采用 Lucene 语法。词法、语法由上游解析器负责，项目仅维护字段语义和数据库适配。

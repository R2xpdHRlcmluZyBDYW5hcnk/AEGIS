# 本地模型研判

## 规则缓冲区核查

2026-11-05，MCP Search Service。查询前复用既有 HTTP Host、规则候选和固定引擎资料，补充核查 URI、TLS 状态及 content 编码。查询条件为 Snort 3 官方 http_uri、http_header:field host、ssl_state:client_hello 和 content 十六进制写法。

来源：[HTTP URI](https://docs.snort.org/rules/options/payload/http/uri)、[HTTP Header](https://docs.snort.org/rules/options/payload/http/header)、[TLS 状态](https://docs.snort.org/rules/options/payload/ssl)、[content](https://docs.snort.org/rules/options/payload/content)。结果：HTTP URI / Header 具有独立缓冲区，Host 可以字段选择；ssl_state 检查可见握手状态；content 支持混合字符串与十六进制字节，特殊分隔符须转义或编码。它们不提供任意加密 HTTP/3 请求解析，也不能从日志签名推断未采集的载荷。

威胁狩猎、概览、安全事件和阻断记录的事件详情使用同一个研判组件与提示词。点击总结按钮后才调用模型，有真实会话 ID 时总结会话，否则总结单条记录；打开、重开或返回详情均不会自动推理；从会话列表打开的日志不重复嵌套会话列表。所有事件入口均保留“生成规则建议”，只有点击后才生成。规则动作默认告警，也可明确选择阻断匹配特征。总结和建议只在当前详情中显示，不写入事件库。规则建议在服务端内存保留最多十分钟、最多十六条，并绑定登录会话；只有“添加并应用规则”会提交变更。

## 接口与资源

Web 后端以流式 HTTP 连接本机 `127.0.0.1:18080/v1/chat/completions`，模型为 `Qwen3.5-2B`，关闭思考。会话总结最多两次顺序推理：狩猎计划最多 224 token，最终分析最多 384 token；整个请求共用 180 秒期限与单个推理槽位。没有会话 ID 时仍可根据可信事件时间及元数据计划附近检索，不推断会话身份。适配同机单并发、2048 上下文、无状态部署，不新增模型代理。`ips-web.conf` 的 `local_llm.enabled=false` 可关闭功能，生产配置和认证保留在源码仓库外。

`POST /api/ai/generate` 接收 summary / rule 和事件查询标识，后端重新读取事件，禁止客户端传任意提示词或证据。响应为逐行 JSON。只有一个推理槽位，不排队；证据查询仍经过已有有界查询调度，模型等待不占用规则修改锁或查询工作线程。对模型只发送字段白名单中的摘要、通信地址、签名和有限网络样本，不发送原始载荷、认证配置或完整事件 JSON。系统提示词与输入合计限制为 1500 个 UTF-8 字节，为 384 个输出 token 和消息模板保留余量；超限时删除完整样本、候选或摘要字段，不截断 JSON 或规则条件。输入不是完整事件，提示词明确要求披露证据不足。

浏览器用 AbortController 持有流式请求，关闭详情、返回、切换详情或页面、卸载页面时取消。切换浏览器标签页或浏览器失去焦点时继续生成。后端在等待模型期间每 0.2 秒检查客户端连接，断开后关闭上游流式套接字，触发模型服务的原生断线取消。不会调用影响其他客户端的全局 `/v1/abort`。取消时丢弃输出，不创建规则。网络中断的发现依赖 TCP / 代理断线传播；不能承诺操作系统或 NPU 在绝对零延迟内停止。反向代理须保留流式响应及断线传播，响应带 `X-Accel-Buffering: no`。

## 提示词与规则边界

提示词在 `llm_assistant.py` 维护。SUMMARY_PROMPT 用于全部事件入口，允许分析正常通信、可疑活动和威胁事件，不强制把会话归类为攻击。输出通信概览、行为与处置、研判依据、建议核查；要求区分事实、推断和证据缺口，不把告警等同于入侵成功。HUNT_PROMPT 提供真实字段与 Lucene 语法，让模型自主选择行为条件和是否检索。RULE_PROMPT 提供受限的 Snort 3 编写知识，说明实际特征、缓冲区、方向、动作和误报边界；模型返回候选编号、描述、选择依据、误报限制，TCP 报头候选还可选择同包附加条件。

## 会话证据与狩猎

后端根据事件的真实 `session_id` 使用已有索引检索同一会话的全部已保留记录，不以源目的地址、五元组、Community ID 或原生 UID 猜测会话关联，也不局限于当前列表的时间窗口。没有引擎会话 ID 时保留为单条证据分析。查询使用既有只读快照和有界调度；不让模型直接访问数据库、文件系统、命令行或任意 SQL。

输入优先保留通信两端与协议、日志类型及处置计数、最新连接状态和双向流量、检测签名与规则身份、实际动作，以及 DNS、TLS、HTTP 等代表性记录。流量取最新连接记录的值，不对累计更新反复求和；统计值由后端计算。HTTP URL 仅保留路径，不发送查询字符串、原始报文或认证配置。最终输入优先保留命中摘录，合并重复证据，并明确为部分字段摘要。模型输入较小时会省略较低优先级细节；界面显示会话总记录数与实际证据摘录数。

模型先读取实际通信端点、协议 / 应用、状态、域名、包量 / 字节量和其他可用元数据，自主提出最多两条 Lucene 条件及核查目的。输入仅提供字段类型与观测事实，不提供预设查询、候选查询编号或强制的告警核查。模型可以验证行为假设、比较其他地址的相似通信，并搜索尚未触发规则的流量；没有有意义的假设时可不查询。正常会话也允许提出核查，但不能仅因假设或命中就归类为攻击。

关联检索默认搜索其他会话，既不强制当前 session_id，也不要求命中当前 IOC 或已有告警。真实会话 ID 仅用于读取当前事实和排除当前会话；没有 ID 时保持附近候选语义，不猜测归属。后端绑定事件附近最多 45 分钟的窗口，每条查询最多 240 字、48 个谓词节点、12 层深度，字段仅限元数据白名单，必须完整编译为参数化 SQL。不得查询载荷、身份键、任意时间边界、SQL 或命令。

每次最多两项关联查询，顺序执行；每项共享三秒只读执行预算，沿用有界查询名额，关闭详情时取消等待和正在执行的 SQL。不循环扩展查询，不增加模型轮数。只返回日志命中数及最多四个不同会话的代表性摘录，避免一个连接的重复快照占满结果。对有身份的候选同时核对保留日志中的检测记录数；零记录仅代表保留范围内未见检测，不能证明正常或完整无告警。普通连接的状态与双向流量和当前事件依据一并送入最终总结。

语法不合规、计划截断或执行失败会明确显示，不执行自然语言、不用固定模板替换模型条件、不把失败当作零命中。模型计划为空时直接总结当前证据。跨会话命中始终是候选线索，不并入当前会话，不触发封禁或规则写入。“查看命中日志”保留实际谓词、时间范围及排除条件。

DNS 候选关联由 `dns_context.py` 查询同一客户端此前的 DNS 答案，要求答案 IP 与连接对端一致，并检查查询时间及已采集 TTL；没有 TTL 时使用较短的保守窗口。SNI / Host 一致的名称优先，最多保留两项，供模型判断。DNS 与后续连接保持独立会话，界面明确显示候选关系。这只能补充可见线索，不能证明应用使用了某次解析，也无法恢复缓存之外、加密 DNS 或未采集的查询。

支持的示例条件：

```text
type:alert OR type:anomaly OR action:blocked
type:http AND status:[400 TO *]
type:dns AND rcode:NXDOMAIN
level:high AND action:allowed
```

异常状态或命中条件不是恶意活动的充分证据；未命中也不能证明安全。计数按入库日志记录统计，alert / drop 可能分别记录同一处理过程，不代表独立攻击次数；不同查询的命中可以重叠。界面保留实际执行的搜索词、范围和命中数，“查看命中日志”以相同条件打开威胁狩猎。规则生成及应用仍是独立的明确操作。

规则候选由后端提取实际特征，包含 HTTP Host 结合方法和路径、可见 TLS ClientHello 域名、DNS 名称字节、异常 TCP 标志结合同包 TTL / TOS / 窗口 / 长度，以及具体 OpenAppID 应用。没有仅按源目的地址生成规则的兜底。URI 去除查询字符串，特殊字节用十六进制编码；模型不能增加任意选项、命令、未观察特征或自行改变动作。服务端将候选编译为受限规则，再由实际引擎校验。默认 alert，用户可在生成前选择 block，预览中说明相应影响。证据不足时不生成。

HTTP / TLS / DNS 名称本身不能证明恶意。HTTP Host 使用子串匹配；TLS 规则仅在可见 ClientHello 中匹配域名字节，并非严格的 SNI 专用缓冲区；DNS 规则匹配未压缩名称字节，需核查覆盖与误报。ECH、加密 QUIC 内部请求及不可见内容不能据此检测。报头条件仅从同一采样包组合，不能拿不同时间的字段拼成不存在的包。

事件证据尽量保留无需原始载荷的会话、应用、DNS / HTTP / TLS / SSH / 文件元数据，以及原生扩展采集的 IP、TCP、ICMP 报头字段。包字段明确附带采样时间和方向，属于最近可见原始包的采样，不代表逐包历史。元数据不能覆盖任意 content / pcre / byte_* 等内容规则的写作依据；不虚构未采集字节。字段缺失时保持空值，不推断其不存在或正常。

`POST /api/ai/rules/add` 只接收本会话建议令牌，不能替换规则原文。独立规则管理器分配未与活动及待应用规则文件冲突的 SID，并启动 manual-add 事务。规则只写入 `ips-web-hunting.rules`，由现有 Snort 配置独立 include；不交给订阅规则合并器，不改写订阅规则文件，不应用其他待处理配置。Snort `-T` 验证整个活动配置后热重载，失败恢复旧文件，重载失败则尝试恢复旧规则集。成功后把已应用规则同步到待应用快照，保留其余待应用编辑。提交记录支持重启后恢复同步。重复点击同一建议返回同一任务。

规则应用是已明确确认的配置事务，开始后继续完成或回滚；关闭详情只停止模型生成。应用结果可在规则管理任务日志查看。生成建议未通过实际引擎校验前不标记为有效规则。

## 来源核查记录

查询日期：2026-11-04。来源：MCP Search Service，Snort 官方 Rule Writing Guide。查询前检查 `docs/rule-source-verification.md`、`docs/snort3-engine.md` 和本项目规则管理源码；既有记录没有覆盖本次 HTTP 规则提示词的全部内容，因此补充读取以下页面。条件：传统规则头、content 字符串和修饰符、HTTP Host 缓冲区、flow、sid 和配置校验。

- [Rule headers](https://docs.snort.org/rules/headers/)：传统规则头描述动作、协议、地址、端口和方向。
- [content](https://docs.snort.org/rules/options/payload/content)：字符串内容匹配、转义和逗号修饰符。
- [http_header](https://docs.snort.org/rules/options/payload/http/header)：HTTP 头缓冲区支持 field 限定；本实现限定 host。
- [flow](https://docs.snort.org/rules/options/non_payload/flow)：流方向与连接状态条件。
- [sid](https://docs.snort.org/rules/options/general/sid)：规则身份选项。
- [Configuration](https://docs.snort.org/start/configuration)：Snort 3 使用 Lua 配置；最终配置由实际引擎验证。

本地服务协议依据部署资料 README 与服务配置中的 stream、enable_thinking、单并发和无状态约定，以及取消实现中流式断开触发原生 abort 的逻辑。狩猎语法依据 Luqum 解析器、`hunt_query.py` 的 AST 校验、`hunt_sql_pushdown` 和字段目录；会话关联依据引擎会话身份与数据库索引。

2026-11-05，MCP Search Service 补充核查 [flags](https://docs.snort.org/rules/options/non_payload/flags)、[ttl](https://docs.snort.org/rules/options/non_payload/ttl)、[window](https://docs.snort.org/rules/options/non_payload/window)。条件为异常 TCP 标志与同包整数报头约束；结果确认相应规则选项的写法。HTTP、TLS、DNS、TCP 报头和 AppID 候选及显式 block 动作另由匹配版本的实际 Snort 二进制执行配置验证；文档语法并不替代实际引擎校验。

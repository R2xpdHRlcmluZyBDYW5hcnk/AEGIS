# 元数据采集与检测可见性

AEGIS 的基础调查模型是连接身份、生命周期、双向包与字节计数、应用识别、协议事务、签名事件和采集健康。连接用引擎会话身份关联，不用五元组或时间相近强行合并。日志条数与连接数分别统计，生命周期更新不重复累加连接流量。它覆盖常见元数据型 NDR 的基础层，但不代表已经具备行为基线、跨主机攻击链关联或所有协议解码能力；本项目不使用没有定义的“NDR 合规”认证口径。

## 会话记录与重复诊断

原生会话记录分别表示首次观察、TCP 状态变化、AppID 变化、活动连接周期快照和结束。同一会话出现多条记录属于时间线；32 次状态变化上限与 30 秒快照间隔约束其开销，快照不重新计算连接总数。协议事务和连接结束摘要另有证据用途，不能仅按五元组删除。

连接结束后拒绝迟到的包完成回调，防止已释放的观察状态被同一旧身份重新创建。扩展代码热替换时，新观察器可能为仍活动的会话补一条首次观察，这不创建新的连接身份；结束后的身份不能再追加观察。回归覆盖 ICMP 阻断、普通生命周期、周期快照及扩展热加载。

协议异常可能在同一连接的多个包上重复触发，和签名告警分开保存。`anomaly_gid`、`anomaly_sid` 用于数值筛选与详情展示，不赋予异常告警级别，也不把它们计入签名告警数。新记录保存这两个投影字段，旧记录不进行后台重写；原始证据仍保留编号。对重复异常进行合并前必须同时定义次数、首次及最后发生时间、包边界和故障重放的幂等性，不能直接丢弃后续记录。


## 重叠签名来源

同一 GID:SID 在合并结果中只加载一条签名。按来源分组禁用仅移除该来源的候选，其他来源仍可能提供同一签名；需要全局停用时按 GID:SID 禁用。告警抑制仍可能保留阻断动作，不能与禁用混用。选择来源时同时比较签名覆盖、修订号及策略默认启用状态。两个来源的签名内容重叠，不代表其默认启用策略也一致。

依据：2026-11-07 Australia/Perth，核对 [Snort 官方 Community FAQ](https://www.snort.org/faq/what-are-community-rules)。Community 是订阅签名的子集，每日更新；使用延迟签名时仍可能提供更及时的补充。LightSPD 名称本身不能证明账号订阅权限；结合当前归档比较，不能把一次缓存覆盖推断为未来所有更新都冗余。

## 内容留存边界

检测器继续在内存中检查报文并重组协议，以保留内容签名的检测能力。配置显式禁止文件内容捕获、文件调试数据输出及报文日志器；不保存 PCAP、请求体、响应体或提取的文件内容。文件类型与 SHA-256 属于调查元数据，继续保留。HTTP URI、域名、文件名、SSH / TLS 握手等已选协议字段仍会留存，这里的“不记录 payload”指不保留原始报文和应用正文，并不表示协议元数据没有敏感性。

`snort.lua` 保留完整采集长度、HTTP / HTTP2、DNS、TLS、SSH、FTP、文件及 AppID 检查器。固定版本的 HTTP extractor 同时接收 HTTP/2 事务，不增加不存在的 `http2` 服务配置。去掉空 `file_id` 动作配置和无法在关闭捕获时产生有效值的 `extracted*` 输出。删除固定版本缺少发布方的原生 QUIC handshake 订阅，独立 [QUIC 观察组件](quic-observer.md) 保持不变。

JSON 告警回退保留：部分解码异常发生在连接建立之前，不经过 notice extractor，不能仅因有两类告警输出就删除回退路径。桥接层继续执行现有去重。会话状态 / 应用变化及有界 30 秒更新保留，以供持续连接和时序调查。

## 字段与健康指标

| 内容 | 使用与边界 |
| --- | --- |
| HTTP 请求 / 响应体字节数 | `http_request_bytes` 与 `clen` 可检索、展示；只是长度，不包含正文。请求长度由原生 `request_body_len` 映射。新增入库记录支持该字段过滤；旧库自动增加可空列，不在启动时重写历史记录，旧行的请求长度仍需查看保留的原生元数据 |
| DNS 查询、答案、类型、返回码及 TTL | 固定版本的原生 extractor 以响应触发；没有收到响应的查询不能据此计算完整超时率，不虚构 request 事件 |
| TLS 与 QUIC 握手 | 保留实际可观察字段；不宣称恢复加密 HTTP 内容或全部连接迁移关系 |
| NFQUEUE 积压 | 使用当前 `queue_total`，不使用 nftables 的累计包数。无权限、读取失败或状态过期时保持未知 |
| 队列溢出 / 用户态投递丢包 | 分别读取内核的 `queue_dropped` 与 `queue_user_dropped`，不互相替代；属于累计计数 |
| 解码丢弃、TCP 重组缺口、ACK 异常 | 独立展示，不能直接相加视为网络丢包。计数受引擎重启、签名与流量影响 |
| 重组字节 / 分段上限 | 显示重组队列限制触发计数。没有观测到资源上限压力时，不盲目增大内存上限或关闭校验；应结合持续增量和资源预算调整 |
| 检测事件阈值抑制 | `detection.event_limit` 记录事件过滤器抑制的告警，不能解释为检测队列满、内存不足或网络丢包；不会据此放宽资源上限 |

系统页沿用原有卡片、字体、配色与描边状态徽标。概览显示实际积压和两类累计丢包；详细解析计数放在系统页。采样错误继续显示已有时间与陈旧状态，未知值不伪装成零。

## 验证方法

在开发电脑运行 `tests/check_ndr_metadata.py`，需要与项目补丁匹配的 Snort 二进制及依赖；通过 `SNORT_ENGINE_PREFIX` 指定独立安装目录。测试先校验完整配置，再回放合成 HTTP 正文与 DNS / 连接流量：正文签名必须命中，请求体长度必须准确，全部日志不得出现正文标记或 PCAP 文件。它验证该配置与样本，不能代替所有第三方签名、插件或协议的审计。

Go 状态与资源回归验证未知值、独立丢包计数和状态传递；tests/angular-go-backend.mjs 通过真实 Go 合成预览验证页面导航、指标及桌面布局。所有数据回放在开发电脑执行，设备只做必要只读取数。

## 依据

2026-11-07（Australia/Perth，UTC+08:00）先复用 [Snort 引擎记录](snort3-engine.md) 的固定版本与 QUIC 边界，再直接查询官方固定标签源码和手册；查询条件为文件捕获、调试输出、extractor 字段与 HTTP/2 订阅、NFQUEUE proc 列定义，以及常见连接和协议日志覆盖范围。固定源码直接读取比泛化搜索更准确。结果：

- [Snort 3.12.4.0 extractor 手册](https://github.com/snort3/snort3/blob/3.12.4.0/doc/user/extractor.txt)及 [HTTP extractor](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/extractor/extractor_http.cc)支持所选请求 / 响应长度与 HTTP/2 事务；[extractor 模块](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/extractor/extractor.cc)定义可配置服务。
- [文件模块](https://github.com/snort3/snort3/blob/3.12.4.0/src/file_api/file_module.cc)与 [文件策略](https://github.com/snort3/snort3/blob/3.12.4.0/src/file_api/file_policy.cc)区分类型、签名、内容捕获与调试输出；[默认配置](https://github.com/snort3/snort3/blob/3.12.4.0/lua/snort.lua)提供检查器基础配置。
- [Linux NFQUEUE 实现](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/nfnetlink_queue.c)的 `seq_show` 明确定义队列积压和两类丢包的列顺序；队列满与用户态单播失败走不同计数分支。它解释计数语义，不证明任何设备上的具体丢包根因。
- [TCP 统计项](https://github.com/snort3/snort3/blob/3.12.4.0/src/stream/tcp/tcp_module.cc)定义重组缺口与排队字节 / 分段上限；[检测事件过滤路径](https://github.com/snort3/snort3/blob/3.12.4.0/src/detection/fp_detect.cc)在阈值过滤后增加 `event_limit`，与 [事件队列配置](https://github.com/snort3/snort3/blob/3.12.4.0/src/events/event_queue.cc)不同。此次按固定版本实际递增位置核对，避免仅按计数器名字推断含义。
- [Zeek 日志目录](https://docs.zeek.org/en/current/reference/logs/index.html)作为常见连接、协议、文件及诊断元数据的设计参考；它不是适用于本产品的认证标准。是否足以覆盖某个检测场景仍需按协议、可见流量与签名验证。

# Snort 引擎集成

面板消费 Snort 3 extractor 与 alert_json 日志，通过 Unix 控制套接字查询运行状态及执行规则重载。原生日志由 `ips-event-bridge` 转为持久事件流，Web 查询与规则操作分离。

## 来源和构建边界

可选引擎工具固定 Snort 3.12.4.0、LibDAQ 3.0.28 与 OpenAppID 来源，版本、URL 和 SHA-256 见 `build_tools/snort-sources.json`。归档哈希由项目固定，不等同于上游签名。第三方源码、下载物和二进制在源码树外处理，不提交到面板仓库。

`build_tools/build-snort3-arm64.sh` 在 Linux 交叉构建 Debian 13 ARM64、glibc 2.41 目标；`setup_wsl.py` 为 WSL Debian 安装该工具所需软件包。该路径是可选集成工具，不是面板的通用运行要求。构建和安装会修改指定的工具目录，执行前审阅路径与依赖。

PulledPork3 独立安装。面板仅通过 `IPS_PULLEDPORK` 指定的入口传递配置并读取候选结果，不包含更新器修改，也不负责它的安装或升级。

## 会话标识

`build_tools/patch_snort.py` 给固定版本 Snort 增加 `session_id`，补丁采用上游 GPL-2.0-only，许可见根目录 THIRD_PARTY_NOTICES.md。Linux getrandom 生成进程前缀，原子序号标识逻辑会话，热重载不重置；随机前缀不作数学绝对唯一承诺。

面板保留原生 uid，但只按完整 session_id 关联。没有 ID 的事件独立保留，不用五元组、时间窗或 UID 猜测归属。使用其他 Snort 版本或缺少扩展时，先核对日志字段和原生校验结果。

## 验证

`tests/check_snort_native.py` 提供本地合成流量回放；`build_tools/check_arm64_inline.py` 提供完整 ARM64 内核下的 NFQUEUE 测试。用户态 QEMU 的结果不能替代内核内联测试。引擎、测试虚拟机和规则归档均单独准备，不随源码分发。

官方接口来源：[extractor 字段](https://github.com/snort3/snort3/blob/3.12.4.0/doc/user/extractor.txt)、[LibDAQ NFQ 实现](https://github.com/snort3/libdaq/blob/v3.0.28/modules/nfq/daq_nfq.c)、[Snort 规则动作](https://docs.snort.org/rules/headers/actions)。日志字段以实际引擎输出为准，缺失内容不作推断。

## QUIC 与 HTTP/3 能力边界

核查时间：2026-11-04 12:31 UTC。查询前检查本文与已有规则来源记录，既有记录没有覆盖 QUIC 解析来源。MCP Search Service 查询条件为固定标签 `3.12.4.0` 的 QUIC extractor、QUIC 事件发布接口、AppID 实现及检查器目录；同时只读核对已部署二进制的版本、模块与插件列表、已加载协议库以及配置，不读取真实会话日志、不回放流量。

核查结果：当前二进制为 3.12.4.0，包含 `stream_udp`、AppID、extractor、HTTP 和 HTTP/2 检查器，模块和插件清单未列出 QUIC 或 HTTP/3 检查器。当前配置包含 QUIC handshake 日志绑定及版本、连接 ID、SNI、客户端应用协议字段，但配置接收日志事件不等价于具有生成事件的协议解析器。没有发现当前进程加载额外 QUIC / HTTP/3 协议解析库。

- [extractor 文档](https://github.com/snort3/snort3/blob/3.12.4.0/doc/user/extractor.txt)列出 QUIC handshake 及连接 ID、SNI、客户端协议字段，并定义 UDP 连接计数与状态。
- [extractor_quic.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/extractor/extractor_quic.cc)订阅 QUIC ClientHello 与握手完成事件后记录数据。
- [quic_events.h](https://github.com/snort3/snort3/blob/3.12.4.0/src/pub_sub/quic_events.h)定义事件接口；[AppID 构建清单](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/appid/CMakeLists.txt)与 [第三方 AppID 接口](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/appid/tp_appid_utils.cc)不能独立证明已部署可用的 QUIC 解析来源。

MCP 未能打开检查器目录且未定位到事件产生器，因此补充通过 GitHub 官方 tree API 与官方固定标签源码归档进行内存检索，不保存第三方源码。完整目录未截断；QUIC 专用文件只有 extractor 与 pub/sub 接口。检索事件发布标识只定位到接口定义和 extractor 订阅，未发现相应发布实现。AppID 中存在 QUIC 身份及外部事件处理，不等同于提供握手解析器。

据已部署模块与源码核查，可确认 UDP 流层会话标识、时长、双向包数和字节数的记录链路；不能把当前实例视为已具备完整 QUIC / HTTP/3 协议级会话检测。QUIC 握手元数据的实际产出尚未做流量验证，不能仅凭配置宣称可用；HTTP/3 请求、响应内容及独立请求流的协议级解析也没有已部署检查器支持。UDP 流记录不能用作 QUIC 连接迁移或 HTTP/3 多路流跟踪能力的证明。

## 流事件关联与入库

2026-11-04 追加核查，MCP Search Service 查询条件为规则 `flow` 的含义、固定标签 `3.12.4.0` 的连接 extractor 与会话身份实现。查询前复用上面的引擎和会话记录；补充读取 [flow 规则选项](https://docs.snort.org/rules/options/non_payload/flow)、[连接 extractor](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/extractor/extractor_conn.cc)及 [通用 extractor 字段](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/extractor/extractors.h)。前者控制方向、建立状态、重组等规则匹配条件，不是面板日志合并 API。连接 extractor 订阅 FLOW_END；原生 UID 优先使用 connection_id，否则取 FlowKey 哈希。

使用与部署二进制 SHA-256 一致的本地副本，在开发环境回放完全合成的 HTTP / DNS 报文及同五元组复用场景。告警、HTTP 事务与连接结束日志共享引擎 session_id；新连接得到新 session_id，样例的原生 UID 被复用。`tests/check_snort_sessions.py` 将这些输出继续送入正式解析和事件库，并验证以单个告警时间打开详情仍能查询同会话的已保留日志。用户态回放不等同于生产流量完整性证明。

入库修复移除了新表的旧 UNIQUE(ts,type,sid,src,dst,sport,dport) 约束。该约束未包含生成器、会话及原始记录身份，合成测试可复现不同证据被 INSERT OR IGNORE 丢弃。仅 event_key 对完全相同的来源记录进行幂等去重。既有非空数据库不会在启动时自动重建；需要经过明确的历史清理或离线迁移后才获得新表结构。

时间范围比较保留毫秒列中的小数部分，避免对微秒级上界取整后排除边界记录。会话详情扩大为整个已保留会话范围；网络记录仍分页，告警证据有明确截断标志。活跃连接尚未产生 EOF、协议未产出事务记录、缺少会话 ID、存储保留期限及采集丢包应分别排查，不能统称为合并失败，也不能把事件日志当作完整报文留存。

`history-reset` 支持 scope=database：串行维护任务仅暂停控制台，将事件库与 WAL、SHM、派生统计库完整移到受保护备份目录，创建带新 clear_epoch 和统一事件流读取位置的空库，再恢复控制台。检测引擎、桥接采集与原生日志不停止；认证、规则、配置、资产和备份保留。旧统一事件不重新导入。默认 scope=all 仍是已有的完整历史清理流程。

## QUIC 追踪组件评估

2026-11-04 追加 MCP 查询：Snort 外部插件、Zeek QUIC、Mercury QUIC、Wireshark QUIC 字段与 TShark 资源生命周期，以及 RFC 9000 / 9312 的连接迁移限制。复用前述引擎核查后补充以下来源：

- [Snort 外部插件](https://github.com/snort3/snort3_extra)：官方目录 API 完整树未发现 QUIC / HTTP3 专用路径，不能据此配置一个不存在的检查器。
- [Zeek QUIC 日志](https://docs.zeek.org/en/current/scripts/base/protocols/quic/main.zeek.html)：记录版本、初始 CID、SNI、客户端 ALPN 等；这些字段本身不证明支持全部迁移或加密请求解析。
- [Mercury](https://github.com/cisco/mercury)：可捕获 QUIC 握手并生成 JSON，内存与工作线程可配置；其 README 仍将软件标为 beta，不能直接当作已验证的完整连接追踪器。
- [Wireshark QUIC 字段](https://www.wireshark.org/docs/dfref/q/quic.html)：支持可见 DCID、SCID、连接编号及握手相关字段；字段清单不等价于本项目已经接入。
- [TShark 手册](https://www.wireshark.org/docs/man-pages/tshark.html)：支持过滤输出及 -M 周期性重置解析状态。采用时必须处理状态重置及内存上限，不能永久依赖解析器内部连接编号。
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)与 [RFC 9312](https://www.rfc-editor.org/rfc/rfc9312.html)：CID 用于路径变化后的连接路由；新 CID 可通过加密帧发布，被动观察者不能保证关联所有 CID 轮换。初始 ClientHello 提供的 ALPN 不能独立证明最终协商结果。

目标为被动连接与握手追踪，尽量关联可见路径变化；不要求终端密钥，不宣称恢复加密 HTTP/3 请求。需要以合成握手、CID 复用与歧义、路径改变、零长度 CID、未知 / 截断数据和资源上限验证后，才可启用新增采集组件。

实现与安装见 [QUIC 观察组件](quic-observer.md)，它不改变 Snort 检查器能力声明或原生会话归属。

## 同版本手册与日志含义

补充核对用户提供的 Snort 3.12.4.0 User Manual、Reference Manual 和 Developers Guide。User Manual 的 extractor 章节将 conn 的 EOF、HTTP / HTTP2 的 EOT 请求响应事务、TLS metadata 等定义为不同事件。一条连接摘要的包计数可以大于一，不能由包数推导事件条数，也不能在应用未识别时虚构协议事务。

同章说明 TCP 负载字节按首个已见序列号与下一期待序列号计算，流重启会重置相关值。零字节不足以独立证明没有负载，需要结合观察范围与报文。事件抽屉提供同会话证据分页与刷新；关联调查查询全部已保留会话记录并支持实时更新，避免固定在首次点击时的时间上界。

连接 extractor 的 ts 是触发记录时的报文时间，包括延迟清理场景，不保证等于该连接最后报文时间。适配器保留原生 duration，不再由 ts 减 duration 推算连接起止时间；查询层同时屏蔽旧原生连接记录中这两个推算值。具有显式报文起止时间的其他来源不受影响。延迟 EOF 测试覆盖新记录、历史行显示及狩猎查询，避免将估算时间作为观测事实。

## 官方开发案例与排障资料

查询时间：2026-11-04 14:38 UTC。查询前复用本文的固定版本源码、手册及本地回放记录；已有内容没有覆盖用户反馈案例与 NAT 挂钩位置。使用 MCP Search Service 查阅 Snort Additional Resources、官方 GitHub issue、固定标签源码和 nftables 挂钩说明；GitHub 页面未完整呈现评论时，以 GitHub 官方 API 补充核对正文和维护者回复。查询条件包括 Snort 3 NFQUEUE 多线程日志缺失、单向流量、FlowData 状态与 extractor UID。结果如下：

- [Snort issue #170](https://github.com/snort3/snort3/issues/170)：2021 年 NFQ 队列配置讨论中，提问者报告多线程有流量但没有预期的 JSON 输出，维护者指出各包线程分别写日志。检查全部线程文件是必要步骤；这个案例不能证明所有日志缺失都是线程文件问题。
- [Snort issue #379](https://github.com/snort3/snort3/issues/379)：2024 年用户报告 Snort 3.3.4.0 的 NFQ / ICMP 丢失现象。维护者要求核对 iptables 和规则，并未复现；它只证明存在相似反馈，不能作为当前版本缺陷或当前现场根因的证据。社区评论中未经证实的根因说法不采用。
- [FlowData 官方接口](https://github.com/snort3/snort3/blob/3.12.4.0/src/flow/flow_data.h)明确用于给 Flow 附加检查器状态。实际案例为 [HttpFlowData](https://github.com/snort3/snort3/blob/3.12.4.0/src/service_inspectors/http_inspect/http_flow_data.h)及 [HttpInspect 状态访问](https://github.com/snort3/snort3/blob/3.12.4.0/src/service_inspectors/http_inspect/http_inspect.cc)：通过 p->flow 访问连接，使用 get_flow_data / set_flow_data 维护状态。create_flow_data_id 生成检查器状态类型的槽位 ID，不能当成每条连接的唯一 ID。
- 连接日志应参照固定版本 extractor 的 FLOW_END 订阅和日志字段，不从规则 flow 选项反推日志条数。若要跨多种日志保留稳定身份，需要在引擎逻辑会话生命周期中统一分配并输出 ID，处理结束、重启、超时和进程重启；仅用五元组哈希无法区分后续复用的连接。当前项目的补丁与合成回放验证遵循这一边界。
- [Additional Resources](https://www.snort.org/documents#AdditionalResources)中的 [多线程处理](https://www.snort.org/documents/snort-3-multiple-packet-threads-processing)可用于理解分线程输出。[重组丢包文章](https://www.snort.org/documents/possible-packet-loss-during-reassembly-for-snort-ids-ips-sensors)针对 Snort 2.9.7，提示排查网卡聚合、校验和和采集范围；其中旧配置和截断长度示例不能直接套用到 Snort 3。README.stream5、早期 Perfmon 资料也应按历史资料使用。本文未依据这些文档修改生产网卡选项。

## NAT 采集范围验证

[nftables 官方挂钩说明](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)将 mangle 排在 -150，目的 NAT 排在 -100；同一挂钩按数值递增执行。[LibDAQ 3.0.28 NFQ 文档](https://github.com/snort3/libdaq/blob/v3.0.28/modules/nfq/README.nfq.md)展示双向 FORWARD 入队，并不规定面板必须在 DNAT 前入队。

当前生成器在 prerouting / mangle 入队，且提前跳过 fib daddr type local。`tests/check_nfq_nat.py` 在开发电脑的独立 Linux 网络与挂载命名空间中创建 RFC 5737 测试端点和 masquerade：在 -150 的计数位置可见请求，反向 NAT 尚未还原的回包被本机目的排除；相同排除条件在 -90 可见双向报文。计数器代替队列以隔离挂钩与排除逻辑，不测试 NFQ verdict 或 Snort 内核内联能力。测试不连接实际设备，并在退出时释放命名空间。

该复现确认旧规则组合对普通 masquerade 路径存在覆盖缺口，不能证明某条历史记录一定经过该路径。修复将专用 prerouting 链调整为 -90，在目的 NAT 后、源 NAT 前执行，保留队列分发和排除条件。现有基于标记的 TUN 路由规则继续保留；此修改不提供路由器本机 OUTPUT 流量采集。隔离 Linux 实测验证专用表的原子更新和回滚后，经独立 NFQUEUE 部署器应用。部署后新产出的原生日志已在开发电脑确认存在双向 TCP 摘要，以及同一会话的协议事件和连接摘要；这不构成所有连接均无丢包的证明。历史日志不重写或清理，跨越切换时刻的连接可能仍不完整。

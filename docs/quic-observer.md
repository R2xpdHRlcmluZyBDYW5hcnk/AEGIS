# QUIC 连接与握手观察

Go 可选采集组件复用 Wireshark / TShark 的协议解析及连接关联，不自行实现 QUIC 解密器。dumpcap 只捕获指定接口的 UDP，通过有界管道交给 TShark，不保存报文文件。面板只接收字段白名单内的观察记录。

## 安装和资源

核定环境是 Debian 13，版本与来源固定在 `build_tools/quic-sources.json`，安装使用 APT 的签名元数据及包校验，不混用其他 Debian 分支的系统库。

```powershell
.\deploy.ps1 -Target user@host -UpdateBackend -QuicInterface eth0
```

接口应选择实际承载流量的一侧，避免在 NAT 两侧重复采集。接口只写入设备的 `/etc/ips-quic-observer.json`。普通控制台更新不会自动启用组件，也不改变既有接口。启用时安装运行依赖、建立受限服务用户、配置独立服务及日志轮转，不重启 Snort。

服务使用 Linux capabilities 捕获流量，限制为 CPUQuota=50%、MemoryHigh=192M、MemoryMax=256M、TasksMax=16。解析器每处理 100000 个输入包重置内部状态；适配器最多保留 4096 个观察会话，每个会话保留最多 16 个 CID 和 8 条路径。资源上限与状态重置会影响观察覆盖，记录不能当作完整抓包。

## 身份和字段

观察会话使用独立进程随机前缀与序号生成 session_id。Wireshark 连接编号只在当前解码进程和重置区间使用；不同区间、不同解码连接不按五元组猜测合并。可见路径变化沿用解析器确认的关联；缺少初始握手、零长度 CID、未知 CID 轮换或歧义输入不能保证继续关联。

可搜索 `type:quic`、`observer:"Wireshark QUIC"`、`sni:example.test`、`alpn:h3`、`quic_cids:...`、`coverage:passive_visible`。alpn:h3 只表示客户端提出 HTTP/3，不能独立证明最终协商结果。不使用终端会话密钥，不恢复加密 HTTP/3 请求、URL、响应或完整多路请求流。

字段包括 SNI、客户端 ALPN 提议、版本、可见 CID、路径和观察计数。只有观察到 ClientHello 且方向可确定时才投影客户端 / 服务端计数；否则保留原始 A / B 观察事实。计数为捕获点看到的 UDP 负载与报文，不保证无丢包，不排除重传。

握手信息完善、路径变化和周期更新可产生多条 quic 记录，它们不是独立攻击。累计更新取最新值，不能反复求和。不额外生成 flow 行，避免再次加入 Snort 连接总量。原始观察 JSON 保留部分覆盖标志与限制信息。

持久日志目录中的 `0_quic_observer.json` 由现有事件桥接器统一入库。观察身份与 Snort 原生身份隔离，不凭地址和时间将 Snort 告警归入另一组件的会话。关闭详情只取消 LLM 推理，基础采集持续运行。

## 验证与来源

`backend/internal/console/runtime_maintenance_test.go` 覆盖身份、重置、路径变化、资源限制、歧义、缺少握手及入库口径。`tests/check_quic_observer.py` 使用本地合成的 example.test 握手和路径变化 PCAP 验证真实解析器和 Go 观察入口：

```sh
python3 -B -m tests.check_quic_observer --tshark /path/to/tshark --pcap /path/to/synthetic-quic.pcap --observer /path/to/ips-quic-observer
```

回放在开发电脑进行。部署后只检查服务、资源限制、采集通道和正常生产记录，不在检测设备生成流量或运行回放、压测。

2026-11-04，MCP Search Service。查询前复用 `docs/snort3-engine.md` 的 QUIC、Wireshark 字段及状态重置记录，补查 Debian 13 包及安全维护分支：

- [Debian tshark 包](https://packages.debian.org/trixie/tshark)和 [安全跟踪](https://security-tracker.debian.org/tracker/source-package/wireshark)列出 trixie-security 的 4.4.19-0+deb13u1、testing / sid 的 4.6.9。选择目标系统受维护的稳定安全分支，保持 ABI 和依赖组合，不带入 testing / sid 依赖。
- [QUIC 字段](https://www.wireshark.org/docs/dfref/q/quic.html)和 [TShark 手册](https://www.wireshark.org/docs/man-pages/tshark.html)定义可见 CID、连接编号、字段输出及 -M 重置。
- [RFC 9312](https://www.rfc-editor.org/rfc/rfc9312.html)说明加密 CID 更新等被动可见性限制。

本地实际解析使用 Wireshark 4.4.19。握手样例由 aioquic 1.7.2 生成，该库不成为面板依赖。样例覆盖 QUIC v1 握手及相同可见 CID 下的源端口变化，不扩大为所有版本、CID 轮换或网络环境的支持证明。

状态重置会重新编号 frame.number。输出过滤保留每个解析周期的首帧，即使它不是 QUIC，避免过滤掉重置边界后将复用的连接编号误合并。首帧标记只更新生命周期，不产生 QUIC 事件。重置时提交待写观察并清空连接状态，随后分配新会话身份；真实解析器回归覆盖重复 Initial 跨多个重置周期。CPU 限额下可能发生采集丢包，覆盖范围始终标记为部分观察。

运行入口为 `ips-quic-observer`；Go 适配器按自身服务的 CPU 分配建立有界解析队列，并按原始顺序更新会话。原 Python 实现已删除，详见 [Go 运行服务](go-runtime.md)。

# 主动拒绝响应

`reject` 动作计数只说明特征动作被调用，不能代替实际 TCP RST 抓包。验证时需同时检查客户端连接是否立即重置，以及网络接口上是否出现向两端发送的 RST。UDP 没有 TCP RST；本项目默认 `reject = {}` 使用 TCP 双向重置，ICMP 响应默认关闭。

2026-11-04 使用开发电脑的 WSL 发起 `curl -4 --noproxy www.testmyids.com --max-time 8 http://www.testmyids.com/`，在部署设备上只读抓取该目标的 RST。现有 SID 498 动作为 reject，验证得到双向 RST、curl 退出码 56 和连接重置，未收到正文。未修改检测引擎或特征。此结果仅证明该 IPv4 路径，不泛化为所有协议、地址或触发时机。

## 固定版本的发送边界

查询前复用 `snort3-engine.md` 的 Snort/LibDAQ 版本和来源。MCP Search Service 查询 `site.github.com/snort3/snort3 act_reject reset active_response attempts` 与 `site:docs.snort.org reject reset active attempts` 未返回可用结果；网页抓取固定标签部分文件也不可用。随后直接从清单指定的官方 HTTPS 归档读取源码并校验 SHA-256，不保存第三方源码到项目目录。

- [act_reject.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/actions/act_reject.cc)定义默认 TCP 双向重置和 ICMP 默认关闭。
- [active.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/packet_io/active.cc)在 DAQ 无法注入时使用 libdnet 的 `ip_send`；该路径记录 `active.injects` 和 `active.failed_injects`。不能把 `ips_actions.reject` 当作注入成功次数。
- [NFQ 实现](https://github.com/snort3/libdaq/blob/v3.0.28/modules/nfq/daq_nfq.c)没有实现直接包注入。所用 ARM64 `libdumbnet1` 1.18.0-2 的 `ip_send` 反汇编使用 AF_INET 和 IPv4 目标地址偏移，未提供这条路径的 IPv6 发送支持。未启用发送适配库时，IPv4 验证不能覆盖这个边界。

原生 notice 提取器的字段表不包含 priority/class，缺失级别时须显示未评级，不能仅凭特征存在就假设威胁级别。来源：[extractor_detection.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/network_inspectors/extractor/extractor_detection.cc)。

## IPv6 发送适配库

`native_response.c` 为项目自有的独立共享库。它保留 libdnet 原有句柄及 IPv4 发送实现，为已经由 Snort 编码完成的 IPv6 响应使用 Linux AF_INET6 原始套接字。每个原生句柄缓存一个 IPv6 套接字，关闭时一并回收；发送错误继续传回 Snort 的失败计数。它不重写检测特征、报文内容或 Snort 二进制。

`tests/check_native_response.py` 在开发电脑 WSL 的临时目录构建该小库，启动完整 ARM64 内核，以现有 Snort 二进制运行 IPv4、IPv6 四队列测试：正常请求放行，block 请求丢弃，reject 请求立即重置，之后正常请求可恢复，注入成功且无注入失败。虚拟机、依赖下载及测试二进制在结束时清理。已验证文档测试地址的全局单播路径；带接口 scope 的 IPv6 链路本地地址未作兼容性承诺。

构建导出：`deploy.ps1 -NativeResponse -BuildOnly -OutputDirectory <源码树外目录>`。激活：`deploy.ps1 -Target root@sensor.example -NativeResponse -NativeResponsePackage <导出的归档>`。该部署会短暂停止检测引擎并重启，普通 Web 更新不会启用或切换发送库。

激活前检查包摘要与 ELF 架构、备份库和 systemd 配置；暂停特征任务和定时维护，停止检测后等待桥接采集读完原始文件，再停止桥接。原始文件在日志磁盘内重命名到 `.response-<时间>-<进程号>`，不复制稀疏大文件或删除证据。新引擎实例使用新日志。启动后核对四队列、加载库及受保护文件与数据库标识，失败自动恢复原库与配置并保留日志。只有 ips.service 通过独立 systemd 配置加载该库，控制台保持原环境及 CPU 分配。

采集完成检查在停机前固定实例 epoch 与启动时间，避免服务停止后读取已被 systemd 清理的运行时目录。检查范围与桥接器一致：空文件和早于当前实例的旧文件保留归档，只有当前实例的非空文件必须具有匹配 inode、epoch 且已消费到末尾的检查点。未消费的当前实例记录仍阻止激活。


将定向抓包保存在开发电脑系统临时目录后，可运行 `python -B tests/check_response_capture.py <本地 pcap>` 检查 IPv6 TCP RST 方向和校验和。工具不显示设备地址；只接受经典 pcap 的 Ethernet、Linux cooked v1/v2 链路，检查直接承载 TCP 的 IPv6 报文，不支持 IPv6 扩展头或 pcapng。

“清空历史事件”同时清理上述已验证的原始日志归档目录；程序及配置回滚备份仍保留。

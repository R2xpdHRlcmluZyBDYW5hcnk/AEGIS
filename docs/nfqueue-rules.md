# NFQUEUE 规则维护

## 生成位置与策略

入队位置为 prerouting 优先级 -90，即目的 NAT 之后、源 NAT 之前。反向 masquerade 回包先恢复客户端目的地址，再经过本机地址排除与队列分发，避免旧 -150 位置将回包排除。现有路由标记和 TUN 回注继续经过同一队列策略。更改挂钩只影响之后经过的报文，不恢复历史缺失证据；切换期间跨越两个位置的既有连接可能仍不完整。

`ips-supervisor` 的 `nft_rules()` 生成 `table inet ips`，独立布局安装路径为 `/opt/ips-console/bin/ips-supervisor`，兼容旧路径 `/usr/local/bin/ips-supervisor`。首条规则为 `iifname "lo" return`；其余接口继续经过本机地址、广播和组播排除规则，最终使用带 `bypass` 的 0–3 号队列。`/etc/nftables.conf` 不参与这次更新。

## 单独部署

在开发电脑运行 `.\deploy.ps1 -UpdateNftRules -Target root@<router-address>`。该入口只准备生成器和部署器，不构建前端；本地回归通过后上传并验证 SHA-256。部署器拒绝生成函数以外的程序逻辑变更，先用目标设备的 `nft -c` 校验生成规则与替换事务，再原子更新生成器文件。已有 base chain 不能直接更改挂钩优先级，因此在一个 nft 原子事务内重建专用 inet ips 表，按快照保留规则和计数器，只改变优先级；其他表不参与事务。计数器快照不包含读取与提交之间新增的计数，不能据此计算切换期间的精确包数。

部署备份保留在 `/var/backups/ips-nft/<UTC时间>/`，包含原生成器、完整回滚事务和原队列表。部署后核对磁盘代码、运行规则、表策略及守护进程和 Snort 3 的 PID、启动时间；核验失败恢复代码和原队列表。不修改认证、设备配置或数据库，也不重启服务。`tests/check_nfq_nat.py` 在隔离 Linux 环境验证反向 NAT 覆盖和真实内核原子更新、回滚。

## 运行中生成器的限制

Python 守护进程已加载的函数不会随磁盘文件更新而变化。这种不停检测的部署立即更新运行规则，并在下次正常启动时加载新生成器；在此之前，如果 `table inet ips` 被清空，旧进程仍可能按旧策略重建它。此期间应避免重载或清空该表；必要时重新执行单独部署。部署器不会为了刷新进程内函数而重启检测引擎。

## nftables 语法来源

- 来源：Netfilter 官方 nft(8) 手册，https://netfilter.org/projects/nftables/manpage.html 。
- 查询条件：读取官方手册；检索 `iifname "lo"`。
- MCP 查询结果：手册说明 `nft -c` 只检查命令而不应用；接口字面值的精确示例未在该次查询中命中。最终部署语法必须用目标设备的 `nft -c` 验证。

Snort 3 为每个队列使用独立检测线程。默认队列哈希保留连接分配；不使用按当前 CPU 分流的 fanout，以免连接方向进入不同线程。部署前以本地完整 ARM64 内核的四队列合成流量验证。

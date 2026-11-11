# NFQUEUE 规则维护

## 生成位置与策略

入队位置为 prerouting 优先级 -90，即目的 NAT 之后、源 NAT 之前。反向 masquerade 回包先恢复客户端目的地址，再经过本机地址排除与队列分发，避免旧 -150 位置将回包排除。现有路由标记和 TUN 回注继续经过同一队列策略。更改挂钩只影响之后经过的报文，不恢复历史缺失证据；切换期间跨越两个位置的既有连接可能仍不完整。

Go `ips-supervisor --nft-rules` 生成 `table inet ips`，独立布局安装路径为 `/opt/ips-console/bin/ips-supervisor`，兼容旧路径 `/usr/local/bin/ips-supervisor`。首条规则为 `iifname "lo" return`；其余接口继续经过本机地址、广播和组播排除规则，最终使用带 `bypass` 的连续队列，数量由承载 Snort 的检测服务 CPU 分配决定。`/etc/nftables.conf` 不参与这次更新。

## 单独部署

在开发电脑运行 `.\deploy.ps1 -UpdateNftRules -Target root@<router-address>`。该入口只准备部署器，不构建前端；本地回归通过后上传并验证 SHA-256。部署器使用已安装 Go 程序输出的实际队列规则，先用目标设备的 `nft -c` 校验规则与替换事务，并保留程序二进制。已有 base chain 不能直接更改挂钩优先级，因此在一个 nft 原子事务内重建专用 inet ips 表，按快照保留规则和计数器，只改变优先级；其他表不参与事务。计数器快照不包含读取与提交之间新增的计数，不能据此计算切换期间的精确包数。

部署备份保留在 `/var/backups/ips-nft/<UTC时间>/`，包含原生成器、完整回滚事务和原队列表。部署后核对磁盘代码、运行规则、表策略及守护进程和 Snort 3 的 PID、启动时间；核验失败恢复代码和原队列表。不修改认证、设备配置或数据库，也不重启服务。`tests/check_nfq_nat.py` 在隔离 Linux 环境验证反向 NAT 覆盖和真实内核原子更新、回滚。

## 队列健康与恢复

`ips-supervisor --status` 显示当前实例实际队列的监听状态。守护进程每秒读取内核 NFQUEUE 状态。单个队列连续缺少监听满 15 秒时，守护进程等待特征事务释放配置锁，取得锁后再次核对队列，然后只重启 Snort 子进程。启动尚未就绪时有 120 秒宽限。读不到内核状态时不累计缺失时间。恢复后须再次观察到全部队列就绪，才允许处理下一次掉线，两次自动重启至少间隔三分钟。

自动重启保留当前队列分流策略。Snort 退出后，守护进程最多等五秒让事件桥接追平，再在同一日志目录内重命名 Snort 的原始日志。未追平的记录保留在 `.response-*` 归档中。独立 QUIC 采集与 Web 控制台继续运行。检查针对监听缺失，队列保持注册但处理缓慢时不触发这项恢复。

通过 `.deploy.ps1 -UpdateSupervisor -Target root@<router-address>` 单独激活守护更新。部署核对运行中的队列策略，备份守护程序后重启一次 `ips.service`，等待按检测服务分配的全部监听和 Snort 控制套接字就绪。部署验证失败时恢复旧程序。备份位于 `/var/backups/ips-supervisor/`。


NFQUEUE 单独更新要求已安装 Go supervisor；旧 Python 安装应先执行 UpdateSupervisor。

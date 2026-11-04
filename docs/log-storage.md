# 持久日志存储

## 依据

2026-11-03，MCP Search Service 查询：`site.freedesktop.org software systemd man latest systemd.mount bind RequiresMountsFor local-fs.target`、`site.man7.org linux man-pages man8 logrotate maxsize hourly copytruncate`。

查询结果：[systemd.mount](https://www.freedesktop.org/software/systemd/man/257/systemd.mount.html) 说明本地挂载默认排在 `local-fs.target` 之前；[systemd.unit](https://www.freedesktop.org/software/systemd/man/257/systemd.unit.html) 说明 `RequiresMountsFor` 建立挂载依赖；[logrotate 手册](https://man7.org/linux/man-pages/man8/logrotate.8.html) 说明 `maxsize` 仅在工具运行时检查，`copytruncate` 存在复制与截断之间的丢日志窗口。

补充核查：2026-11-03，MCP Search Service 直接读取 Snort 3.12.4.0 的 [file_connector.cc](https://raw.githubusercontent.com/snort3/snort3/3.12.4.0/src/connectors/file_connector/file_connector.cc) 与 [file_connector_module.cc](https://raw.githubusercontent.com/snort3/snort3/3.12.4.0/src/connectors/file_connector/file_connector_module.cc)。写入端用 `std::ios::out` 打开文件，配置项不含追加模式；文本消息末尾添加换行。结合本地副本中的稀疏前缀及后续有效 JSON，可确认 copytruncate 不能重置该写入端的文件偏移。

采集器识别 NUL 填充，支持时通过独立文件描述符的 `SEEK_DATA` 跳过稀疏区，避免破坏缓冲读取位置；不支持时按字节预算分批跳过。超出单条上限的记录按持久丢弃状态恢复到下一换行，不再使整个进程退出。正常的未完成短行仍等待后续内容。原始文件不由采集器修改，拒绝计数和稀疏跳过字节数保存在检查点中。

## 布局与维护

持久布局支持直接路径模式，标记中的 `direct_paths` 为 true 时，检测与桥接使用 `/var/lib/ips-snort-logs/snort`，事件流使用 `/var/lib/ips-snort-logs/events/events.json`。服务环境与权限配置使用相同目录，不依赖可能被父挂载遮盖的 `/var/log` 别名。Web 的私有存储标记不可读时，通过管理员配置的服务环境确定只读日志路径。

`deploy.ps1 -Target root@sensor.example -UpdateBackend -MigrateLogs` 可将已有绑定布局切换到直接路径。该事务会短暂停止检测与控制台，校验并保存当前可见日志、被遮盖的持久日志、程序和配置，只迁移事件流读取边界，不删除事件数据库。失败恢复旧程序、配置与读取边界，并保留本次产生的日志。恢复入口位于该次备份的 `rollback.sh`。

直接路径修复支持源日志卷已满的情况：停止写入后复制并校验原始日志和事件流，在目标磁盘通过正式桥接器的 `--drain` 模式补齐完整记录，再恢复服务。未完成的末行保留在备份，检查点随事务备份和回滚；不要求故障卷先恢复写入能力。

清空历史事件在删除前、重启后均检查日志布局。旧绑定布局必须与持久目录具有相同设备号和 inode；仅有迁移标记或挂载单元显示 active 不算有效。挂载不符时拒绝清空，避免在回退目录重建日志并报告成功。直接路径模式使用统一目录，连续清空不会切回 `/var/log`。兼容绑定单元排在本地文件系统及可用的日志初始化服务之后，避免启动顺序覆盖。

首次迁移入口将日志存到 `/var/lib/ips-snort-logs`，通过 systemd bind mount 保留 `/var/log/snort` 与 `/var/log/ips` 接口。服务依赖对应挂载，避免重启后回落到原来的小容量日志分区。迁移不修改检测二进制、规则、认证及事件记录。

切换前停止检测、排空采集并停止控制台，现有日志复制到 `/var/backups/ips-log-storage` 并校验 SHA-256。原生日志保存在迁移备份，新的引擎实例从空日志开始；控制台事件流保留内容。若存在清空数据库的读取边界，仅迁移其文件身份，保留原偏移，避免跨文件系统复制后回灌旧事件。

原生日志达到 16 MiB、事件流达到 64 MiB 时轮转，各保留两份轮转文件，每分钟检查。阈值不是硬磁盘配额；检查间隔内允许继续增长。原生日志使用 `copytruncate`，采集器检查偏移前的内容摘要，识别截断后迅速增长的文件；不能据此承诺消除 logrotate 本身的复制/截断窗口。迁移快照不纳入自动轮转删除。

首次绑定迁移在切换成功后才释放原分区上已验证备份的旧日志；直接路径修复保留原可见日志和持久目录中的旧日志。迁移备份提供 `rollback.sh`，回滚保留持久磁盘上的新日志，恢复原日志布局与原配置；需要再次短暂停止服务。

`deploy.ps1 -UpdateBackend -ClearNativeLogs` 显式清理已消费的原生日志前缀、轮转归档及迁移前日志快照。活动文件通过 Linux hole punching 清除检查点确认已消费的前缀，保留 inode、写入偏移和未读取尾部；不移除引擎仍在使用的文件名。检查点身份或摘要不匹配时跳过该文件。控制台事件流、事件数据库、规则及认证保留。删除快照日志后，配置回滚仍可使用，但只恢复空日志目录，不能恢复已删除的旧日志。


增加 -ClearEventStream 时，清理范围扩展为全部原生日志内容和控制台事件流。先暂停规则任务与轮转，停止桥接、等待控制台读完已有事件流，再停止控制台。对原生日志捕获清理边界并打洞，保留写入端描述符；完整记录边界后产生的数据继续采集，截断的半条记录从检查点跳过到下一换行。控制台事件流换成新 inode 的空文件，数据库只更新读取边界元数据，历史事件、清空标记、统计库、规则、认证均保留。最后恢复桥接、控制台和轮转。检测引擎始终运行；清理完成后会继续产生新日志，文件逻辑大小可能保留稀疏前缀，不代表旧内容仍存在。此模式必须明确授权全量原始流清理后使用。

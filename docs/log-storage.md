# 持久日志存储

## 依据

2026-11-03，MCP Search Service 查询：`site.freedesktop.org software systemd man latest systemd.mount bind RequiresMountsFor local-fs.target`、`site.man7.org linux man-pages man8 logrotate maxsize hourly copytruncate`。

查询结果：[systemd.mount](https://www.freedesktop.org/software/systemd/man/257/systemd.mount.html) 说明本地挂载默认排在 `local-fs.target` 之前；[systemd.unit](https://www.freedesktop.org/software/systemd/man/257/systemd.unit.html) 说明 `RequiresMountsFor` 建立挂载依赖；[logrotate 手册](https://man7.org/linux/man-pages/man8/logrotate.8.html) 说明 `maxsize` 仅在工具运行时检查，`copytruncate` 存在复制与截断之间的丢日志窗口。

补充核查：2026-11-03，MCP Search Service 直接读取 Snort 3.12.4.0 的 [file_connector.cc](https://raw.githubusercontent.com/snort3/snort3/3.12.4.0/src/connectors/file_connector/file_connector.cc) 与 [file_connector_module.cc](https://raw.githubusercontent.com/snort3/snort3/3.12.4.0/src/connectors/file_connector/file_connector_module.cc)。写入端用 `std::ios::out` 打开文件，配置项不含追加模式；文本消息末尾添加换行。结合本地副本中的稀疏前缀及后续有效 JSON，可确认 copytruncate 不能重置该写入端的文件偏移。

采集器识别 NUL 填充，支持时通过独立文件描述符的 `SEEK_DATA` 跳过稀疏区，避免破坏缓冲读取位置；不支持时按字节预算分批跳过。超出单条上限的记录按持久丢弃状态恢复到下一换行，不再使整个进程退出。正常的未完成短行仍等待后续内容。原始文件不由采集器修改，拒绝计数和稀疏跳过字节数保存在检查点中。

## 布局与维护

持久布局支持直接路径模式，标记中的 `direct_paths` 为 true 时，检测与桥接使用 `/var/lib/ips-snort-logs/snort`，事件流使用 `/var/lib/ips-snort-logs/events/events.json`。服务环境与权限配置使用相同目录，不依赖可能被父挂载遮盖的 `/var/log` 别名。Web 的私有存储标记不可读时，通过管理员配置的服务环境确定只读日志路径。

旧版绑定挂载迁移曾在 `/var/backups/ips-log-storage` 保存原日志、程序、配置及读取边界。已有迁移的回滚使用相应备份内的 `rollback.sh`，恢复原布局时保留持久磁盘上的新日志。此回滚需要短暂停止相关服务。

清空历史事件在删除前、重启后均检查日志布局。旧绑定布局必须与持久目录具有相同设备号和 inode；仅有迁移标记或挂载单元显示 active 不算有效。挂载不符时拒绝清空，避免在回退目录重建日志并报告成功。直接路径模式使用统一目录，连续清空不会切回 `/var/log`。兼容绑定单元排在本地文件系统及可用的日志初始化服务之后，避免启动顺序覆盖。

原生日志达到 16 MiB、事件流达到 64 MiB 时轮转，各保留两份轮转文件，每分钟检查。阈值不是硬磁盘配额；检查间隔内允许继续增长。原生日志使用 `copytruncate`，采集器检查偏移前的内容摘要，识别截断后迅速增长的文件；不能据此承诺消除 logrotate 本身的复制/截断窗口。迁移快照不纳入自动轮转删除。

清空历史的两种范围及对应的数据影响见 [历史管理](history-management.md)。

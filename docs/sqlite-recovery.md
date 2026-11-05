# SQLite 事件库损坏检查与恢复

## 官方依据

核实日期：2026-11-01。MCP Search Service 查询条件：

- `site:sqlite.org WAL reset bug 3.46.1 database corruption checkpoint`
- `site:sqlite.org corruption reindex integrity_check index repair`

查询结果及用途：

- [SQLite WAL 文档](https://sqlite.org/wal.html)描述了特定并发写入/检查点条件下的 WAL-reset 缺陷。仅凭版本号、WAL 模式或出现损坏，不能确定它是本次损坏原因；发行版可能另有补丁。
- [SQLite 错误码](https://sqlite.org/rescode.html)和 [REINDEX](https://sqlite.org/lang_reindex.html)区分可重建的索引与数据库其他结构损坏。表 B 树损坏不能假定为只需重建索引。
- [完整性检查](https://sqlite.org/pragma.html#pragma_integrity_check)用于检查页、B 树及约束；快速检查不替代恢复后的完整校验。
- [损坏数据库恢复](https://sqlite.org/recovery.html)明确说明恢复结果可能不完整，返回使用前必须核验数据和约束。
- 同页的恢复选项说明：`--ignore-freelist` 用于避免把已删除内容重新引入；无法归属表的数据应保留在独立的 lost-and-found 表中，不静默丢弃。
- [官方工具下载页](https://sqlite.org/download.html)本次列出的稳定源包为 SQLite 3.54.1，`sqlite-amalgamation-3540100.zip`，官方 SHA3-256 为 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`。恢复工具仅临时构建使用，不据此替换系统 SQLite 库。
- 同日追加 MCP 查询：打开上述官方下载页核对 Windows 工具。`sqlite-tools-win-x64-3540100.zip` 的官方 SHA3-256 为 `e171f3993a992edf076746926dd52b5e2ebfabaee38818e74987e1d8112ab987`。离机恢复仅使用校验通过的临时工具，不安装或替换系统库。
- 2026-11-03 MCP Search Service 再次打开同一官方下载页核对恢复工具，版本仍为 3.54.1，Windows x64 工具包及 SHA3-256 与上述记录一致。
- 同日追加 MCP 查询：[SQLite 文件格式](https://sqlite.org/fileformat.html)的 B 树、varint、record 与索引章节，以及 [SQLITE_DBPAGE](https://sqlite.org/dbpage.html)。索引记录包含索引列及 rowid；DBPAGE 通过 pager 读取页。页级候选只能在离线工作副本上读取，并结合可信事件 ID、时间戳及 统一事件 JSON 原文摘要核对，不能仅凭残留索引页重新引入历史记录。

2026-11-05 Australia/Perth，MCP Search Service 查询 SQLite WAL-reset 的触发条件、[Debian SQLite 3.46.1-7+deb13u2 补丁清单](https://sources.debian.org/patches/sqlite3/3.46.1-7%2Bdeb13u2/)和[官方下载页](https://sqlite.org/download.html)。官方说明此缺陷需要同时写入或检查点的多个连接，SQLite 3.51.3 及更新版本包含修复。Debian 补丁清单未确认这个回移。稳定源码包仍为 3.54.1，散列与上述记录相同。结构损坏报错只能确认库无法完整读取，不能据此确定 WAL 缺陷或物理存储故障。

## 控制台运行库与写入保护

ARM64 发布包可使用 `deploy.ps1 -WslBuild -BuildOnly -WithSqliteRuntime -OutputDirectory <源码外目录>`，复用 `README-deploy.md` 中的 Debian ARM64 交叉构建环境，自动获取并核对固定 SQLite 源码。`deploy.ps1 -UpdateBackend -ReleasePackage <发布包> -Target <SSH 目标>` 在独立服务布局安装专用 SQLite 动态库。发布前校验库能由 Python 载入，启动后从 `/healthz` 核对版本。控制台单独加载此库，其他服务和系统 SQLite 继续使用系统包。源码树只保留构建逻辑。SQLite 交付代码采用公共领域授权，见[上游声明](https://www.sqlite.org/copyright.html)。

原始事件库采用 WAL 和 `synchronous=FULL`，提交时同步 WAL。写入失败先保留待提交批次，回滚失败时停止继续写入。容量回收按已用页计算，空闲页和 WAL 暂时占用不作为删除现有记录的依据。回收使用有界增量清理与 PASSIVE 检查点。新空库在建表前启用增量回收。

历史管理的「仅清空事件库」操作将已停止的控制台数据库、WAL、SHM 与派生统计库作为一个文件组封存，启动空库并核对事件库就绪状态。原始事件流和检测保持运行，新库从切换边界开始收集。备份保留供离线核查。

## 保护边界

先区分检测引擎和控制台事件库。原始数据库、WAL 和可用备份均保留，不在损坏原件上直接执行 REINDEX、VACUUM、恢复导入或删除 WAL。快照必须来自停止写入的完整文件组，或 SQLite 一致性备份接口；不能把运行中文件的随意副本当作一致备份。

恢复工作在副本上进行。校验全部表、索引、事件身份和可恢复记录，不能用“能打开数据库”代替完整性证明。若无法证明完整恢复，明确说明可能损失的范围，再决定是否替换运行库。

## 离线工具

`recover-event-db.py` 只接受已封存的文件组：目录包含 `snapshot.json` 与 `original/`，清单记录 `database_path`，以及以文件名为键的 `files`（每项含 `bytes`、`sha256`）。制作快照时先冻结或停止写入，逐个复制数据库、WAL 和存在的 SHM，复制后再次核实源文件没有变化。冻结期间不得打开数据库；制作完成后停止故障控制台，检测引擎保持运行。

在健康的存储上运行，输出目录必须尚不存在：

```sh
python -B recover-event-db.py --snapshot /path/to/snapshot --output /path/to/new-recovery --sqlite-cli /path/to/verified/sqlite3 --reference /path/to/reference.db
```

工具先验证全部快照校验值，并用含 AUTOINCREMENT 的测试库验证 CLI 恢复链路。然后复制数据库与 WAL 到独立工作目录，不复制 SHM，不用 SQLite 打开封存原件。恢复 SQL 经有界流传输，保留失败日志，任一进程失败都拒绝继续校验。

若全部表可完整读取、损坏仅涉及索引，可加 `--rebuild-indexes`。此模式使用 SQLite 内部的 `INSERT ... SELECT ... NOT INDEXED` 复制全部表及 rowid，在候选中重建索引，并要求源与候选的完整 schema、每张表的全部字段摘要以及序列一致，最后执行完整性检查。任何表不可读、字段变化或结构检查失败均拒绝候选；当前仅支持有 rowid 的表。此模式不需要 SQLite CLI，不调用 `.recover` 或在源库上执行 REINDEX。内部值复制保留空 BLOB、含 NUL 或无效 UTF-8 的 TEXT，避免 shell 克隆路径对这些值的转换。

损坏页可能导出含控制字节或无效 UTF-8 的 TEXT 字面量。工具只将 INSERT 的 VALUES 部分中的这类字面量转换为 `CAST(X'…' AS TEXT)`，保持字节内容，避免把二进制内容直接交给文本输入链路。此操作不意味着字段语义正确；后续仍须核对原库可读字段，并单独审查无法归属或无效的记录。

`--reference` 可选，其文件需来自可信且完整读取的原始索引，包含 `expected(id INTEGER PRIMARY KEY, ts NUMERIC)` 表。验证报告给出完整性检查、各表记录数、外键错误，以及缺失、多出、时间戳不符的身份数量。身份匹配也不能单独证明每个字段完整，报告不会宣称完整恢复，更不会激活或覆盖运行库。无法归属的记录及原始证据应保留待核对。

## 历史记录与停写期间的补录

模块提供 `compare_readable_rows`（逐字段比较并可记录问题 ID）、`scan_index_keys`（只读索引页候选）、`table_row_candidates`、`committed_wal_rows` 和 `forensic_wal_rows`，供离线核对使用。页解码只接受可完整放在页内的记录；溢出记录不会被猜测或截断补入。当前 WAL 检查头部、盐值、累积校验和及提交标记。旧 WAL 世代已失去原头部，取证函数只能验证后续校验连续性及完整事务边界，结果始终是候选，必须再与当前可信 ID、event_key 和时间戳交叉核对；不能把旧世代页重新当作当前数据库页应用。

从 统一事件 JSON 重建时，必须用原文与解析时间生成的 SHA-256 event_key 精确匹配，并核对原索引 ID 与时间戳；多候选或证据不足时不自动选择。可读原记录优先直接复制，恢复候选及原始文件保留。候选库中的其他表、约束和序列也须与原库核对。

停写后积累的日志采用 `find_eve_cursor` 定位最后已存事件的原始行，再用 `replay_eve` 从该行之后补录，保留顺序中迟到的旧时间戳事件。只按最大时间戳截断可能漏掉这类事件。补录使用原有去重约束，新增 ID 大于原索引的最大 ID，不执行容量回收；末尾尚未写完的行留待下一次处理。上述函数只用于离线候选库，不对运行中的事件库执行。

若保留日志中已没有最后已存事件，不猜测游标。核对当前文件及归档的覆盖边界后，可从保留文件起点完整补录，以 event_key 去重；缺失区间需单独说明并在切换前确认。切换前还须核对尚未补录的日志字节范围确实落在 Web 启动补读窗口内，否则继续在本机追平。

## 入库故障状态

写入失败状态独立于查询连接保存，缓存命中也会将故障返回页面，避免旧结果无提示地继续显示。可重试错误在成功提交后清除；SQLite 报告 CORRUPT 或 NOTADB 时停止继续读取 统一事件 JSON、写库和容量回收，保留待提交批次并记录故障日志，等待离线修复。

## 切换与失败处理

只有经过校验并明确接受残余缺口的候选才能切换。先持有部署锁，确认控制台已停止、没有进程打开旧文件组，检测引擎仍运行；记录引擎 PID、线程 CPU 范围及受保护配置摘要。确认 Web 单元独立于检测服务，启动 Web 不会触发检测服务的 Conflicts。

将校验后的候选放在运行目录所属文件系统，核对摘要，补录剩余 统一事件 JSON，并在设备上执行快速完整性检查和历史身份核对。启动前再追平日志游标，避免校验期间积累的日志超出启动补读窗口。

把旧数据库及存在的 WAL、SHM 整组移入受保护备份目录，再原子替换主数据库文件；不要让旧 WAL 与新数据库配对。同步目录后只启动 Web。验证健康端点、认证、查询、新事件入库、规则状态、全部线程 CPU 范围及检测引擎 PID。若切换失败，只停止 Web，封存失败候选文件组并恢复旧文件组；损坏原库恢复后保持 Web 停写，不能自动重新投入写入。封存原件、统一事件 JSON 和可用恢复备份均保留，清理仅限已核实的派生暂存副本。

回归检查使用临时数据库，不接触设备数据：

```sh
SQLITE_RECOVERY_CLI=/path/to/verified/sqlite3 python -B -m unittest tests.test_event_db_recovery -q
```

未提供 CLI 时仍运行清单保护与身份比较用例，真实表页损坏恢复用例跳过；正式恢复前须提供经校验的 CLI 跑完该用例。

# Go 运行服务与生产维护

## 运行入口

发布包使用同一个 Go 程序提供下列入口，按可执行文件名或子命令选择职责。目标机不安装 Go 工具链，运行期不调用 Python。

| 入口 | 职责 | 安装与更新 |
| --- | --- | --- |
| ips-web | HTTP、SSE、事件库与模型接口 | UpdateBackend |
| ips-rule-manager | 签名策略、更新、调度与维护授权 | UpdateBackend |
| ips-event-bridge | 原生日志及 QUIC 观察入库桥接 | UpdateBackend |
| ips-snort-rules | 签名来源与候选生成命令行 | UpdateBackend |
| ips-supervisor | Snort 子进程、NFQUEUE 与队列表恢复 | UpdateSupervisor |
| snort-home-net | 接口 IPv6 前缀刷新、原生校验与重载 | UpdateBackend |
| ips-quic-observer | dumpcap / TShark 字段适配与有界会话观察 | UpdateBackend |
| recover-event-db | 封存事件库的离线恢复与校验 | UpdateBackend |
| ips-maintenance | resources、history-reset 等维护子命令 | UpdateBackend |

构建、安装部署和开发测试工具继续使用 Python。已迁移组件的原 Python 实现和专用依赖已删除；合成兼容样例保留在 backend/internal/console/testdata，回归由 Go 执行。deployment_support.py 仅提供部署客户端和文件校验，不承载运行服务。后端升级在健康验证后备份并移除安装目录内明确列出的旧模块，失败时恢复，既有回滚备份保留。Snort、LibDAQ、系统 nftables、Wireshark 和用于页级恢复的可信 SQLite CLI 保持独立组件；shell 日志轮转入口不属于 Python 运行依赖。

控制台、维护入口与检测守护分别由 backend-build.json、maintenance-build.json 和 supervisor-build.json 记录程序摘要。普通后端更新不替换检测守护。需要切换 supervisor 时单独执行：

```powershell
.\deploy.ps1 -UpdateBackend -Target user@host -ReleasePackage <完整发布包>
.\deploy.ps1 -UpdateSupervisor -Target user@host -ReleasePackage <同一完整发布包>
```

第二步只重启承载 Snort 的 ips.service，不升级引擎二进制，不重启控制台、签名管理器或事件桥接。它短暂停止检测，恢复后核对控制套接字、全部实际队列及既有队列策略。失败时恢复旧守护程序和构建记录，再恢复旧队列数。数据库、签名、认证和管理员已有服务资源分配保留。QUIC 单元切换只在组件原先运行时重启该组件，不自动启用未运行的采集服务。

## 服务资源分配

每个进程启动时读取自身 /proc 状态的 CPU 亲和性，以及其 cgroup 和祖先 cgroup 的 CPU 配额、有效 cpuset。以这些限制的最小值确定预算；CPU 配额按 quota / period 向上取整，最低一个工作单元。支持 systemd 常用的 cgroup v2 及 v1 CPU 配额布局。CPUQuota 继续由内核执行时间配额约束。

Go 调度器、CPU 工作池、前台查询名额、SQL 辅助预算、RPC、HTTP 连接与订阅队列均由该预算派生；工作池排队容量为工作数的两倍。旧 read_workers、IPS_CPU_WORKERS 和固定四线程常量不再覆盖服务的有效分配。单写者、日志顺序、历史事务及模型推理互斥仍按一致性要求串行，完成通知通道不作为工作队列扩容。

Snort 的检测线程和 NFQUEUE 数只依据实际承载检测进程的 ips.service。该服务的第 N 个工作线程接收第 N 个队列，队列从 0 开始连续分配；nftables 继续使用连接哈希和 bypass，不启用 fanout。运行实例记录实际工作数，其他服务的状态汇总与部署验证读取该记录及检测进程参数，不按 Web 服务的资源分配推断队列数。

资源拓扑在服务启动时确定。调整 systemd 分配后重启对应服务生效；运行中的 Snort 不为重新分配队列而自动重启，避免破坏已有连接状态。TasksMax 是进程与线程数量上限，不等价于可用 CPU 数。程序不重置已有 CPUQuota、CPUAffinity 或 cpuset 设置。

```sh
/opt/ips-console/bin/ips-maintenance resources --pid <服务 MainPID>
/opt/ips-console/bin/ips-supervisor --status
/opt/ips-console/bin/ips-supervisor --nft-rules
```

supervisor 优先通过系统 libnftables 的公开 ABI 检查及恢复专用队列表，避免每秒启动 nft 子进程；缺少该库时使用有超时的 nft CLI。恢复检测前与签名事务共用配置锁，并再次确认监听缺失；未知的内核样本不累计掉线时间。启动宽限、单队列缺失宽限及恢复节流保持既有行为。重启前原始日志以原 inode 保留在同文件系统归档，独立 QUIC 日志不被归档或截断。

## 内置签名更新器

AEGIS 的 Go 更新器直接处理 Snort Community、Registered、LightSPD 和自定义文本源，不执行或修改外部 PulledPork3。官方下载使用 HTTPS 与上游发布的 MD5 一致性校验，归档与摘要不一致时有界重试；本地缓存另以 SHA-256 校验。MD5 校验不代表数字签名。Oinkcode 不进入进程命令行、公共日志或仓库。

归档先验证成员路径、类型、重复名称、成员数及解压预算，再读取文本签名、策略和 manifest。LightSPD 按当前引擎依次叠加基础目录和兼容版本增量，按版本数值排序，后面的策略覆盖前面的启用状态和动作；每个选定目录均须具有所选 IPS 策略文件。支持官方 `enable;`、`enable:yes;` 和 `enable:no;` 格式，格式错误仅报告文件名及行号。共享对象模块保持原有范围，不自动部署或执行。签名按 GID:SID 和修订号去重，相同修订保留后加载的签名，保留分组身份及所选 IPS 策略。被启用签名依赖的可用 flowbits setter 以 `alert` 和 `flowbits:noalert;` 补齐，避免依赖签名额外阻断；之后再应用用户禁用及动作策略，不覆盖用户显式禁用。

新解析配方独立标记版本，不复用旧解析器生成的候选缓存；已校验的原始缓存可离线重新生成。候选仍经过原生签名校验和既有原子切换、热重载与失败回滚流程。任何下载、摘要、归档、策略或原生校验失败均保留活动签名。

签名来源列表显示当前 IPS 策略；在 Registered 或 LightSPD 的“配置签名来源”窗口选择 connectivity、balanced、security 或 max-detect，两种官方源共用该设置。保存进入待应用草稿，点击“应用更改”从本地归档重新生成；Community 与自定义文本源不使用该上游策略。包内内置签名通过带 `enable;` 的 Snort 签名状态 stub 应用动作，避免与自动加载的内置签名重复声明；用户禁用及告警抑制仍在后续配置中生效。

手动“更新签名集”在同一事务内应用整份待应用草稿并在线下载，Snort 校验成功后热重载；成功清除草稿，失败恢复原签名和配置并保留草稿。已尝试热重载时再加载恢复后的配置；恢复失败保留事务备份并暂停签名写入。定时更新继续使用生效配置，不提交用户草稿。

## 维护与验证

HOME_NET 刷新复用配置锁，保留手工前缀，仅替换该入口此前维护的 IPv6 前缀。先在独立目录校验完整配置，再原子替换并确认重载；失败时用独立恢复上下文还原并重载。

QUIC 仍由 Wireshark 解码，不新增自制解密器。Go 并行解析字段，使用有界排队和重排缓冲按原顺序更新会话；连接编号的重置、CID 路径变化、容量和部分可见性标记继续保留。输出失败取消读取及解码进程，进程退出提交待写观察。

数据库恢复只接受包含 snapshot.json 和 original 的封存文件组。先校验全组文件摘要，再在全新输出目录复制数据库与 WAL；不打开原件执行 SQLite，不覆盖既有候选，不自动激活恢复库。索引重建在 SQLite 内复制全部可读表值，保留序号、BLOB、非法 UTF-8 TEXT 及 schema。页级恢复使用显式指定并通过自检的 SQLite CLI，流式导入和安全编码损坏的 TEXT；禁止恢复 SQL 附加外部数据库或加载扩展。输出包含完整性和身份对照结果，结构完整不等于已证明恢复全部历史。

```sh
/opt/ips-console/bin/recover-event-db --snapshot /path/to/sealed-snapshot --output /path/to/new-candidate --rebuild-indexes
/opt/ips-console/bin/recover-event-db --snapshot /path/to/sealed-snapshot --output /path/to/new-candidate --sqlite-cli /path/to/verified-sqlite3
```

真实数据的恢复、分析和回放只在开发电脑的临时副本上执行。Go 回归覆盖服务 CPU 分配、动态队列、子进程退出、签名锁、归档 inode、签名下载校验、策略、QUIC 顺序、失败取消、HOME_NET 回滚及封存库恢复；部署回归验证原生程序清单、管理员 CPU 分配保留和启动失败回滚。

## 接口依据

查询时间：2026-11-08 14:39 Australia/Perth（UTC+08:00）。通过 MCP Search Service 核对，查询条件为 Go GOMAXPROCS 与 cgroup 配额、有效 cpuset、LibDAQ NFQ 输入与 libnftables 缓冲 API；现有记录未覆盖自动资源分配及 Go 守护的直接库调用。

- [Go 1.27.3 runtime](https://pkg.go.dev/runtime@go1.27.3#GOMAXPROCS)描述 CPU 数、亲和性、配额和默认 GOMAXPROCS 的关系；默认运行时对小于两核的配额有特殊下限，本项目按实际服务配额明确设置工作数。
- [Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)定义 cpu.max、层级资源限制和 cpuset.cpus.effective。CPU 配额是吞吐量限制，按上述规则转换成软件工作数是本项目的调度选择。
- [LibDAQ 3.0.29 NFQ 实现](https://github.com/snort3/libdaq/blob/v3.0.29/modules/nfq/daq_nfq.c)将输入编号用于队列注册；[NFQ 说明](https://github.com/snort3/libdaq/blob/v3.0.29/modules/nfq/README.nfq.md)说明多实例不能共用同一个队列。
- [Netfilter libnftables 接口说明](https://wiki.nftables.org/wiki-nftables/index.php/Portal:DeveloperDocs/nftables_internals)及 [Debian 13 libnftables 手册](https://manpages.debian.org/trixie/libnftables1/libnftables.3.en.html)定义上下文、命令缓冲和输出缓冲 API。系统库按运行主机已有包提供，不随 Go 程序重新分发。

同日通过 MCP 读取 [Go 官方发布索引](https://go.dev/dl/?mode=json)，最新稳定条目仍为 Go 1.27.3，归档摘要与 build_tools/go-sources.json 一致。签名兼容性以已有签名来源记录和已安装固定版本更新器的只读源码为参照，源码副本仅用于开发核对；没有向外部 PulledPork3 仓库写入。


## PostgreSQL 持久事件库

启用 database_url 后，持久事件进入 PostgreSQL 和 TimescaleDB，SQLite 仅用于有界内存事件池、不可变概览快照和旧库离线恢复。生产部署与回滚入口见 README-deploy.md 的 PostgreSQL 事件存储。

时间、端口与计数采用明确的 PostgreSQL 类型，原始 JSON 继续保持字节一致的 zlib BLOB。MITRE 查询元数据、元组关联摘要和流量显示文字在入库时生成，避免数据库查询时执行 Go 回调。查询层只转换项目生成的 SQL 和参数标记，值始终绑定；SQLite 与 PostgreSQL 共用搜索条件语义。持久只读事务使用 REPEATABLE READ，平行查询导入同一 PostgreSQL 快照。

安全事件的非空会话镜像通过会话、精确时间和分区时间查找，复用现有会话时间索引；其余可空原生字段仍采用空值安全比较。分页最多执行四次查询，签名摘要和阻断状态按整页批量读取，签名条数限制分别作用于每个事件。实时连接已建立时不再为等待首个结果额外启动 HTTP 数据库查询，连接失败的回退与取消机制保留。

签名目录只为当前页构造 JSON，匹配总数继续完整统计。签名管理界面保留最多 12 个近期页签结果，30 秒内返回页签先显示已有结果并立即刷新；手动刷新及编辑后的刷新清空这些结果，过期结果不用于即时展示。

查询依据核对时间：2026-11-09 Australia/Perth（UTC+08:00）。查询条件为 PostgreSQL B-tree 等值比较、部分索引谓词匹配和 Timescale 分块裁剪；来源为 [PostgreSQL 索引类型](https://www.postgresql.org/docs/18/indexes-types.html)、[部分索引](https://www.postgresql.org/docs/18/indexes-partial.html)和 [Timescale 索引](https://www.tigerdata.com/docs/build/performance-optimization/indexing)。执行计划与回归均在开发机临时数据库中验证。

历史清空通过事务内封存应用 schema 和重建读取边界实现，禁止在设备上创建数据库工作副本。只清空事件库保留封存 schema；完整历史清空在采集健康后删除本次封存 schema。失败不会覆盖旧 schema，部署切换支持恢复封存 schema 与旧配置。

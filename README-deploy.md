# 部署与维护

## 运行前提

控制台面向 ARM64 Linux 与 systemd。HTTP、事件入库、规则管理、事件桥接与本地模型接口由 Go 1.27.3 可执行文件提供，目标机不需要 Go 工具链或 Node.js。维护脚本、检测守护与独立安装的 PulledPork3 仍需要 Python 3.13 或更新版本；Snort 3、LibDAQ、规则与 PulledPork3 单独安装。

部署者需确定采集位置、检测模式、HOME_NET、日志存储和访问方式。服务模板不固定 CPU 编号，也不预设具体网卡。先完成 Snort 自身配置校验，再接入面板。

## 构建与传输

在源码根目录执行：

```powershell
.\deploy.ps1 -BuildOnly -OutputDirectory "$env:TEMP\ndr-console-release"
```

输出为 `snort-ndr-<release>.tar.gz` 与 SHA-256 文件。依赖和缓存使用系统临时目录，构建完成后清理。发布包包含 Go 控制台、静态资源及 `backend-licenses.txt`，不附带外部 Snort 引擎或 PulledPork3。

Windows 构建的 Go 部分自动进入 WSL Debian；Linux 构建可直接运行。复用本文引擎构建环境中的 GCC 与 `aarch64-linux-gnu-gcc`，缺失的核定 Go 工具链由构建器自动下载并校验。`backend-build.json` 记录架构、Go / SQLite 版本与四个服务入口的摘要；四个入口使用同一个程序，按服务名选择职责。构建器先运行本机 Go 回归，再生成 ARM64 CGO 产物。SQLite 编译进 Go 程序，不需要额外替换目标机的系统 SQLite。

已有独立布局使用 `deploy.ps1 -UpdateBackend` 切换。部署器核对 ELF 架构、摘要与运行版本，暂停规则任务，备份程序和配置，只停止并重启控制台相关服务，检查 HTTP、管理器和检测进程标识；失败恢复旧程序。既有数据库、认证、规则、设备配置与回滚备份保留。旧 Python Web 代码仅作为兼容性对照，Go 服务不导入或执行这些模块；本地合成对照位于 `backend/internal/console/testdata`。

传输后核对归档 SHA-256；解包后在包目录执行 `sha256sum --strict -c SHA256SUMS`。仅需要静态资源时可运行 `python3 -B build_frontend.py --output /var/tmp/ndr-console-static`。

## 首次接入现有 Snort

以下步骤需要目标主机管理权限。路径为项目默认约定；已有安装先核对冲突并备份，不直接覆盖其配置、规则与运行数据。

1. 配置并验证 Snort 3。`snort.lua` 提供 extractor、alert_json 和本地控制接口配置模板。调整引擎 include、日志及规则路径，将 `home-net.lua` 中 HOME_NET 改为实际监控范围。也可只合并日志配置，保留已有采集服务。
2. 将 `ips-web`、`ips-rule-manager`、`ips-event-bridge`、`ips-snort-rules`、`ips-log-maintenance`、`snort-home-net` 安装到 `/opt/ips-console/bin`，权限为 0755。同时将 `ips_control.py`、`rule_drafts.py`、`snort_engine.py`、`snort_rules.py`、`rule_policy.py`、`parallel_cpu.py`、`parallel_sql.py`、`event_processing.py`、`native_rules.py`、`rule_sources.py`、`rule_identity.py`、`rule_inventory.py`、`runtime_status.py`、`history_reset.py`、`log_storage.py`、`deployment_layout.py` 安装到同目录，权限为 0644。
3. 将生成的 `index.html`、`app.js`、`ui.js`、`app.css`、全部 `chunk-*.js`、`frontend-build.json`、`frontend-licenses.txt`，以及源码中的 `favicon.svg` 安装到 `/usr/local/share/ips-snort-web`。程序与静态目录由管理员所有，Web 用户只读。
4. 以 root 所有、0600 权限将模板安装为 `/etc/ips-snort-web.conf`。将配置中的 static_dir 改为 `/usr/local/share/ips-snort-web`。默认监听 `127.0.0.1:9000`，没有生产密码。执行 `/opt/ips-console/bin/ips-web --gen-password`，将输出的 `password_pbkdf2` 填入配置，私下保存密码。不要提交本机配置或凭据。
5. 创建系统组 `ips-console`，准备 `/etc/snort`、`/var/lib/snort/rules`、`/var/lib/snort/update`、`/var/log/snort`、`/var/log/ips` 与 `/run/snort`。规则模板仅用于新安装，已有规则保留。规则管理器需要配置与规则目录的写权限，事件桥接器读取 Snort 日志并写入 `/var/log/ips/events.json`。隔离 Web 只读该事件流，数据库由 systemd StateDirectory 管理。
6. 生成独立布局的 systemd 单元与布局标记。下面代码在已解包的发布目录以 root 执行，只用于尚未安装控制台的主机；已有安装使用更新流程。它仅安装控制台单元，不启动或替换检测引擎。

```sh
python3 -B - <<'PY'
import json
from pathlib import Path
import runpy
marker = Path('/etc/ips-snort-deployment.json')
units = Path('/etc/systemd/system')
names = ('ips-web.service', 'ips-rule-manager.service', 'ips-event-bridge.service')
if marker.exists() or any((units / name).exists() for name in names):
    raise SystemExit('Existing installation: use the update workflow')
render = runpy.run_path('deploy-snort3.py')['render_unit']
for name in names:
    (units / name).write_text(render(name, Path(name).read_text()))
isolation = units / 'ips-web.service.d/50-isolation.conf'
isolation.parent.mkdir(parents=True, exist_ok=True)
isolation.write_text(render('isolation', Path('ips-web-isolated.conf').read_text()))
marker.write_text(json.dumps(dict(program_dir='/opt/ips-console/bin',
    config='/etc/ips-snort-web.conf', static_dir='/usr/local/share/ips-snort-web')) + '\n')
marker.chmod(0o600)
PY
```

7. 根据实际检测服务调整单元依赖，执行 `systemctl daemon-reload`。先启动 `ips-rule-manager` 和 `ips-event-bridge`，再启动 `ips-web`；确认健康后按需启用开机启动。

引擎路径通过相关服务的 systemd drop-in 设置，默认前缀为 `/opt/ips-snort3/3.12.4.0`：

```ini
[Service]
Environment=SNORT_ENGINE_PREFIX=/opt/snort
```

为 `ips-rule-manager.service` 指定外部更新器入口：

```ini
[Service]
Environment=IPS_PULLEDPORK=/opt/pulledpork3/pulledpork.py
```

更新器需支持面板调用的来源配置、规则输出和离线候选处理接口，能力以安装版本为准。面板不会下载、修补或升级其代码。账户源凭据保存在目标主机 `/etc/snort/rule-update.conf`，权限为 root 0600。

连接关联采用可选的 Snort `session_id` 扩展；缺少该字段时不会推测合并不同事件。来源和边界见 [引擎说明](docs/snort3-engine.md)。

## 可选采集服务

`ips-supervisor` 与 `ips.service` 提供 Linux NFQUEUE 守护。它们接管 `table inet ips`，在 prerouting 分发到 0–3 号队列，使用 bypass。启用前审阅防火墙策略，确保同一队列只有一个检测消费者；不要与已有采集服务同时启用。安装面板不要求启用该守护。

`snort-home-net.timer` 可刷新接口的 IPv6 网段，启用前为对应服务设置 `Environment=IPS_HOME_NET_INTERFACE=<接口名>`，未配置时拒绝执行。日志维护定时器和 `logrotate-snort` 按实际磁盘容量与保留策略配置。

CPU 亲和性与内存限制通过 systemd drop-in 按主机资源设置。修改 NFQUEUE 数量时同步核对引擎线程、启动参数和防火墙规则。

## 访问与验收

先在运行机检查 `curl --fail http://127.0.0.1:9000/healthz`，再使用 SSH 转发：

```sh
ssh -N -L 19000:127.0.0.1:9000 root@sensor.example
```

打开 http://127.0.0.1:19000。共享访问需由部署者配置 TLS 反向代理、访问控制和相应 cookie 设置，再调整监听方式。预览账户只用于本地合成数据夹具。

验收包括登录、事件流新记录、事件查询和服务状态；有规则管理权限时再验证草稿、候选校验及失败恢复。生产主机只做轻量健康检查，完整回归、索引和性能测试在开发机完成。

## 长查询与缓存

交互式事件查询、概览统计与 CSV 导出默认没有执行时长上限。慢查询由有界后台工作队列执行；REST 在计算期间返回 HTTP 202 和 `query_state.status=running`，客户端继续轮询，SSE 发送心跳。相同参数的连接重建复用正在执行的任务；结果返回后短暂保留供并发订阅者读取。第三方客户端须处理 HTTP 202，不能把它当作最终数据。

默认保留一个概览工作线程和最多三个事件查询工作线程，最多接受 16 个不同查询，超额请求返回队列繁忙。执行中的查询使用一致的 SQLite 快照，普通入库和自动历史回收不按执行时间取消查询；显式清空历史、配置变更或服务关闭仍会使相关任务失效。任务保存在当前控制台进程内，重启后须重新发起。长时间磁盘查询可能使 WAL 文件增长，应监控磁盘余量。模型自动关联检索的独立预算和网络连接读写超时继续保留。

最近事件缓存独立预热和追赶；缓存被查询占用时，入库跳过同步缓存合并，再从磁盘游标补齐。普通检索可改用独立只读连接。HTTP 查询遇到过期缓存时等待本次新结果，首屏按刷新间隔更新；不会把已过期的手动查询快照当作最终结果。

## 已安装控制台的更新

SSH 用户需能执行目标端管理操作；每次部署显式指定目标：

```powershell
# 静态资源
.\deploy.ps1 -Target root@sensor.example
# 后端模块与控制台相关进程
.\deploy.ps1 -Target root@sensor.example -UpdateBackend
# 同时应用发布包的 Snort 包装配置并热重载
.\deploy.ps1 -Target root@sensor.example -UpdateBackend -UpdateSnortConfig
# 可选 SSH 密钥
.\deploy.ps1 -Target root@sensor.example -IdentityFile "$env:USERPROFILE\.ssh\sensor_key"
```

这些入口要求目标已按本项目布局运行，不替代首次安装。更新不改变外部更新器。部署检查已知的引擎 PID 文件；外部采集服务应使用自己的健康与进程监控。静态更新校验后原子替换；后端更新先备份和暂停规则任务，再替换程序与验证，失败恢复，保留检测进程、数据库、规则和认证。

`-UpdateSnortConfig` 显式替换 `/etc/snort/snort.lua`，保留其引用的现场网段、抑制配置和规则文件。部署前应比较包装配置中的本地定制；普通更新不启用此选项。配置先备份到 `/var/backups/ips-snort-config`，用当前引擎与已安装会话扩展执行 `-T` 校验，再原子替换并热重载。确认配置代数推进和引擎进程身份不变；失败恢复旧配置并重新热重载。校验输出仅保存在受限备份目录，不输出现场配置。前后端部署与配置部署各自保留备份，配置失败不撤销已健康的控制台版本。

已有包可通过 `-ReleasePackage <归档>` 部署。资源覆盖与迁移选项均需满足对应脚本的前置条件。上传暂存使用磁盘 `/var/lib/ips-deploy`，备份位于 `/var/backups/ips-*`，不使用运行机内存盘保存大型文件。回滚入口以该次部署输出为准，确认新版本健康后再管理备份。

## 可选 ARM64 工具与历史迁移

`build_tools/build-snort3-arm64.sh`、`setup_wsl.py` 与引擎打包器只覆盖清单声明的 Debian ARM64 ABI，见 [引擎说明](docs/snort3-engine.md)。它们不要求面板用户使用 WSL，也不证明其他平台兼容。

`-InstallSnort3`、`-UpdateEngine`、日志迁移和旧引擎清理脚本服务于符合前置检查的历史布局，可能重启检测或移动文件，不属于通用首次安装或日常静态更新步骤。

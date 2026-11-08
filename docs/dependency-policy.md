# 依赖选版与更新

## Node.js apt 安装依据（2026-11-03）

查询前复用本文 Node.js 26.13.0 的已核定记录。通过 MCP Search Service 读取 [NodeSource README](https://github.com/nodesource/distributions/blob/master/README.md)，查询条件为 Debian 的 Node.js 26 apt 仓库安装；该文件将安装说明指向 `DEV_README.md`。随后通过 MCP 读取该说明，确认 Debian 使用签名的 nodistro apt 仓库；MCP 无法读取 setup_26.x 的二进制 MIME 响应，因此不把该响应当作已读脚本引用。

## 选版规则

- 优先采用最新 LTS；官方明确计划进入 LTS 的已发布稳定版本也可采用。
- 没有 LTS 版本可选时，采用最新稳定版。排除 alpha、beta、rc、next、nightly 和其他预发布版本。
- 同时满足上游的 Node.js engines、peerDependencies 和框架兼容表。最新稳定版暂不兼容时，保留兼容分支的最新修订版，记录限制及官方依据；不使用 `--force` 或 `--legacy-peer-deps` 绕过限制。
- 每次维护先核实官方发布信息，再更新工具链清单、精确版本和锁文件。构建使用已核定的固定版本，避免一次发布期间版本漂移。

## 已核定版本（2026-11-01）

核查条件：Node.js 官方发行索引与发布计划；npm 官方注册表各包的 `latest` 标签及 peerDependencies；Angular 官方支持与兼容表。TypeScript 另检查满足 `>=6.0 <6.1` 的全部稳定版本。

| 组件 | 原版本 | 核定版本 | 依据与处理 |
| --- | --- | --- | --- |
| Node.js | 22.22.3 回退工具链 | 26.13.0 | 最新 LTS，代号 Lithium；26 系列于 2026-10-28 进入 LTS |
| npm | 随本机或 Node.js 归档，未单独固定 | 12.2.1 | 注册表最新稳定版，支持 Node.js 26 |
| tslib | 2.8.1 | 2.9.1 | 注册表最新稳定版 |
| parse5（间接依赖） | 8.0.1 | 8.1.0 | 在现有上游依赖范围内更新 |
| weak-lru-cache（间接依赖） | 1.2.2 | 1.2.3 | 在现有上游依赖范围内更新 |
| Angular common/compiler/core/forms/platform-browser/compiler-cli | 22.2.4 | 22.2.4 | 注册表最新稳定版；22 系列处于 Active，官方计划后续进入 LTS |
| Angular build/CLI | 22.2.5 | 22.2.5 | 注册表最新稳定版 |
| ECharts | 6.1.0 | 6.1.0 | 注册表 latest，保持当前版本 |
| RxJS | 7.8.2 | 7.8.2 | 注册表 latest，满足 Angular peerDependencies |
| Zone.js | 0.16.3 | 0.16.3 | 注册表 latest，满足 Angular peerDependencies |
| TypeScript | 6.0.3 | 6.0.3 | 最新稳定版为 7.0.2，但 Angular 22 要求 `<6.1`；6.0.3 为兼容分支最新稳定修订 |

Node.js 27 当前是 Alpha，不符合稳定版要求。选择 Node.js 发布线时查阅官方状态与日程，不仅依据主版本号的奇偶性。

parse5 升级后引入其所需的 entities 9.0.0。锁文件通过核定工具链在临时目录执行 `npm update --package-lock-only --ignore-scripts` 更新；本次 `npm audit` 未报告已知漏洞。间接依赖版本及完整性值以 `frontend/package-lock.json` 为准。

来源：

- [Node.js 发行索引](https://nodejs.org/dist/index.json)、[发行状态](https://nodejs.org/en/about/previous-releases)、[官方发布计划](https://github.com/nodejs/Release/blob/main/schedule.json)。
- [Angular 支持计划](https://angular.dev/reference/releases)、[Node.js / TypeScript / RxJS 兼容表](https://angular.dev/reference/versions)。
- npm 官方注册表：[Angular core](https://registry.npmjs.org/@angular/core/latest)、[common](https://registry.npmjs.org/@angular/common/latest)、[compiler](https://registry.npmjs.org/@angular/compiler/latest)、[forms](https://registry.npmjs.org/@angular/forms/latest)、[platform-browser](https://registry.npmjs.org/@angular/platform-browser/latest)、[compiler-cli](https://registry.npmjs.org/@angular/compiler-cli/latest)、[build](https://registry.npmjs.org/@angular/build/latest)、[CLI](https://registry.npmjs.org/@angular/cli/latest)、[npm](https://registry.npmjs.org/npm/latest)、[tslib](https://registry.npmjs.org/tslib/latest)、[ECharts](https://registry.npmjs.org/echarts/latest)、[RxJS](https://registry.npmjs.org/rxjs/latest)、[Zone.js](https://registry.npmjs.org/zone.js/latest)、[TypeScript latest](https://registry.npmjs.org/typescript/latest)、[TypeScript 版本元数据](https://registry.npmjs.org/typescript)。

## 固定来源与构建

`build_tools/toolchain-sources.json` 固定 Node.js 和 npm 版本。缺少符合版本要求的本机工具链时，构建器在系统临时目录自动获取：Node.js 归档验证官方 `SHASUMS256.txt`，npm 归档验证清单中的官方注册表 SHA-512 integrity。Node.js 自带的 npm 过旧时，单独获取已核定的 npm，不修改本机全局安装。`NDR_NODE` 指定的安装同样接受版本校验。

应用依赖使用 `frontend/package.json` 的精确版本和 `frontend/package-lock.json`。更新间接依赖时在临时目录运行兼容范围内的锁文件更新；生产构建始终使用 `npm ci`，不在构建时临时选择未锁定的依赖。

升级后执行工具链回归、生产构建、产物一致性检查及相关桌面浏览器回归。依赖、下载归档、生成的 MITRE 数据、缓存和测试资料均在临时目录清理。路由器仅运行构建后的静态资源，不安装 Node.js 或 npm。

## Python 搜索依赖（2026-11-04）

根据 [Luqum 官方发行信息](https://pypi.org/project/luqum/)与 [PLY 官方发行信息](https://pypi.org/project/ply/)，核定 Luqum 1.0.0 和其依赖 PLY 3.11；两者没有 LTS 发行线。查询方法、时间和解析器选择见 [事件搜索](event-search.md)。`build_tools/python-sources.json` 固定官方 wheel URL、SHA-256 和许可；构建器预生成匹配的 PLY 表并打包为只读 ZIP。后端发布、前端回归、预览与 `tests/run_backend.py` 自动准备临时依赖，不修改全局 Python 安装。生产运行不访问包仓库。

## Go 后端工具链（2026-11-08）

查询时间：2026-11-08 02:22 Australia/Perth（UTC+08:00，对应 2026-11-07 18:22 UTC）。通过 MCP Search Service 读取 [Go 官方发行索引](https://go.dev/dl/?mode=json)及 [go-sqlite3 官方发行页](https://github.com/mattn/go-sqlite3/releases)。条件为当前稳定版本，排除预发布；同时核对 Linux AMD64、ARM64 官方归档与 SHA-256，SQLite 驱动采用其内置 SQLite，不链接主机的旧 SQLite。

核定 Go 1.27.3、`github.com/mattn/go-sqlite3` v1.14.53，内置 SQLite 3.54.1。版本、归档摘要与来源固定于 `build_tools/go-sources.json`，模块校验值固定于 `backend/go.sum`；构建设置 `GOTOOLCHAIN=local` 和 `-mod=readonly`，运行时不下载依赖。Go 没有单独 LTS 发行线，本次选择官方当前稳定版。

`build_tools/go_backend.py` 自动获取缺失的核定 Go 工具链，所有模块、缓存及下载置于系统临时目录并随构建清理。ARM64 CGO 编译复用项目已有 Debian 交叉编译环境：GCC 14.2.0、binutils 2.44、ARM64 glibc 2.41；准备方式沿用 `README-deploy.md` 的引擎编译环境。Go 服务默认最多四个调度核心，SQLite 连接、前台查询、后台历史与规则来源任务均有独立并发边界。

Go 控制台不加载 Luqum/PLY 或旧 Python Web 模块。发布包仍包含维护脚本、检测进程守护及上游 PulledPork3 使用的 Python 环境；这些与 Go HTTP、规则管理、事件采集和本地模型接口分开维护。

## 研判 Markdown 依赖（2026-11-05）

Australia/Perth，MCP Search Service 查询 [Marked 的 npm 发布信息](https://www.npmjs.com/package/marked)、[渲染器扩展接口](https://marked.js.org/using_pro#renderer)及 [Angular HTML 安全绑定](https://angular.dev/best-practices/security)。核定 Marked 18.1.3 为稳定发行版，MIT，锁文件确认 Node.js >= 20，兼容项目工具链。解析器只在浏览器处理研判文本。原始 HTML 转义为文本，图片与链接渲染标签，HTML 输出通过 Angular 常规绑定净化。

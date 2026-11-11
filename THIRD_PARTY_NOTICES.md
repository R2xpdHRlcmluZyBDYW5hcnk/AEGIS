# 第三方声明

根目录 MIT 适用于本项目独立编写的面板、后端、测试和维护工具。以下第三方材料及派生内容保留原许可，不因本仓库而重新许可。

## Snort 补丁

`build_tools/patch_snort.py` 包含匹配 Snort 3.13.2.0 的上游片段和本项目 session_id 修改，按 GPL-2.0-only 提供，文件内标明维护日期。上游为 [Snort 3.13.2.0](https://github.com/snort3/snort3/tree/3.13.2.0)，完整许可和特别声明见 [Snort-COPYING.txt](LICENSES/Snort-COPYING.txt)，GPLv2 正文见 [GPL-2.0.txt](LICENSES/GPL-2.0.txt)。

`native_session_logger.cc` 使用同版 Snort 的 Flow、TCP tracker、AppID 和插件 API，按 GPL-2.0-only 提供。可选扩展包附带该文件、构建清单及上述许可；需要匹配经过 session 补丁的头文件与运行二进制，不能仅按版本号假定 ABI 相同。

Snort、LibDAQ、OpenAppID 及外部库不提交到源码仓库。可选构建工具的来源和校验值见 `build_tools/snort-sources.json`。另行分发生成的引擎包时，需保留上游版权、许可和适用的对应源码，面板源码包不能替代这些义务。

ARM64 引擎包另含 [Vectorscan](https://github.com/VectorCamp/vectorscan) 5.4.13（BSD-3-Clause），以 Hyperscan 兼容接口提供 NEON 多模式匹配。源码、来源摘要及构建选项由引擎构建清单固定；运行包附带上游 LICENSE，不将第三方源码或编译输出纳入面板仓库。

x86-64 引擎包使用 [Intel Hyperscan](https://github.com/intel/hyperscan) 5.4.2（BSD-3-Clause）。归档、校验值与目标选择同样由引擎构建工具固定，包内保留上游 LICENSE 及其中列出的第三方声明。

## 前端依赖

Angular、RxJS、Zone.js、tslib、Apache ECharts、ZRender、Marked 与构建工具通过 npm 锁文件获取，依赖目录不提交。版本、来源、完整性值和各包声明的许可见 `frontend/package-lock.json`。生产构建提取许可到 `frontend-licenses.txt`，分发静态资源时一并保留。

可选 ARM64 控制台发布包包含按固定官方源码构建的 SQLite 动态库。SQLite 交付代码的公共领域声明与构建方法见 [SQLite 运行库](docs/sqlite-recovery.md#控制台运行库与写入保护)。

## Go 后端

Go 1.27.3 工具链与标准库使用 BSD-3-Clause；`github.com/mattn/go-sqlite3` v1.14.53 使用 MIT，内置 SQLite 3.54.1 交付代码属于公共领域。固定来源见 `build_tools/go-sources.json`、`backend/go.mod` 与 `backend/go.sum`。发布包附带从核定工具链和模块提取的完整 `backend-licenses.txt`；分发 Go 可执行文件时一并保留。数据库驱动通过 CGO 编译 SQLite，目标主机的 glibc 动态库由操作系统提供，不在控制台包内另行复制。

## MITRE ATT&CK

构建器从 `build_tools/attack-sources.json` 固定提交获取并验证数据。完整数据集和生成目录不提交；对应版权与许可原文附入 `frontend-licenses.txt`。数据许可独立于面板 MIT，见 [固定提交 LICENSE](https://github.com/mitre-attack/attack-stix-data/blob/c2494b29dd268c46a5d0ea0990553e4327cd2253/LICENSE.txt)。

## 外部更新器与特征

PulledPork3 的外部安装与仓库保持独立。本仓库的 Go 特征更新器依据 Snort 归档、策略和下载接口独立实现兼容功能，不包含或执行 PulledPork3 源码、补丁或二进制。第三方特征按来源许可及账户权限获取，不随仓库分发。Snort、Cisco、Talos、MITRE 等名称仅用于说明来源和兼容性，不表示官方关联或认可。


## PostgreSQL 事件存储

PostgreSQL 由官方 PGDG APT 仓库安装，使用 PostgreSQL License；TimescaleDB Community 由 Timescale 官方仓库安装，列存功能按 [Timescale License](https://www.tigerdata.com/legal/licenses) 提供。两者软件包、源码和仓库公钥不包含在本项目发布包中。Go PostgreSQL 驱动 pgx 及其依赖版本见 backend/go.mod、backend/go.sum，运行代码的相应许可随 backend-licenses.txt 交付。

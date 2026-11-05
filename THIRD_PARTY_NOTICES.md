# 第三方声明

根目录 MIT 适用于本项目独立编写的面板、后端、测试和维护工具。以下第三方材料及派生内容保留原许可，不因本仓库而重新许可。

## Snort 补丁

`build_tools/patch_snort.py` 包含匹配 Snort 3.12.4.0 的上游片段和本项目 session_id 修改，按 GPL-2.0-only 提供，文件内标明维护日期。上游为 [Snort 3.12.4.0](https://github.com/snort3/snort3/tree/3.12.4.0)，完整许可和特别声明见 [Snort-COPYING.txt](LICENSES/Snort-COPYING.txt)，GPLv2 正文见 [GPL-2.0.txt](LICENSES/GPL-2.0.txt)。

`native_session_logger.cc` 使用同版 Snort 的 Flow、TCP tracker、AppID 和插件 API，按 GPL-2.0-only 提供。可选扩展包附带该文件、构建清单及上述许可；需要匹配经过 session 补丁的头文件与运行二进制，不能仅按版本号假定 ABI 相同。

Snort、LibDAQ、OpenAppID 及外部库不提交到源码仓库。可选构建工具的来源和校验值见 `build_tools/snort-sources.json`。另行分发生成的引擎包时，需保留上游版权、许可和适用的对应源码，面板源码包不能替代这些义务。

## 前端依赖

Angular、RxJS、Zone.js、tslib、Apache ECharts、ZRender、Marked 与构建工具通过 npm 锁文件获取，依赖目录不提交。版本、来源、完整性值和各包声明的许可见 `frontend/package-lock.json`。生产构建提取许可到 `frontend-licenses.txt`，分发静态资源时一并保留。

可选 ARM64 控制台发布包包含按固定官方源码构建的 SQLite 动态库。SQLite 交付代码的公共领域声明与构建方法见 [SQLite 运行库](docs/sqlite-recovery.md#控制台运行库与写入保护)。

## Python 查询解析

Luqum 1.0.0 提供 Apache-2.0 / LGPL 双许可，本项目选择 Apache-2.0；PLY 3.11 使用 BSD-3-Clause。来源与 wheel SHA-256 固定在 `build_tools/python-sources.json`；构建时在临时目录下载、校验并生成 `python-dependencies.zip`，包含各发行包的许可及元数据。第三方代码和生成包不提交源码仓库，部署时随程序分发，运行时不下载或安装包。

## MITRE ATT&CK

构建器从 `build_tools/attack-sources.json` 固定提交获取并验证数据。完整数据集和生成目录不提交；对应版权与许可原文附入 `frontend-licenses.txt`。数据许可独立于面板 MIT，见 [固定提交 LICENSE](https://github.com/mitre-attack/attack-stix-data/blob/c2494b29dd268c46a5d0ea0990553e4327cd2253/LICENSE.txt)。

## 外部更新器与规则

PulledPork3 独立安装，本仓库只包含调用接口，不包含其源码、修改、补丁或二进制。第三方规则按来源许可及账户权限获取，不随仓库分发。Snort、Cisco、Talos、MITRE 等名称仅用于说明来源和兼容性，不表示官方关联或认可。

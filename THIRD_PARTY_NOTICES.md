# 第三方声明

根目录 MIT 适用于本项目独立编写的面板、后端、测试和维护工具。以下第三方材料及派生内容保留原许可，不因本仓库而重新许可。

## Snort 补丁

`build_tools/patch_snort.py` 包含匹配 Snort 3.12.4.0 的上游片段和本项目 session_id 修改，按 GPL-2.0-only 提供，文件内标明维护日期。上游为 [Snort 3.12.4.0](https://github.com/snort3/snort3/tree/3.12.4.0)，完整许可和特别声明见 [Snort-COPYING.txt](LICENSES/Snort-COPYING.txt)，GPLv2 正文见 [GPL-2.0.txt](LICENSES/GPL-2.0.txt)。

Snort、LibDAQ、OpenAppID 及外部库不提交到源码仓库。可选构建工具的来源和校验值见 `build_tools/snort-sources.json`。另行分发生成的引擎包时，需保留上游版权、许可和适用的对应源码，面板源码包不能替代这些义务。

## 前端依赖

Angular、RxJS、Zone.js、tslib、Apache ECharts、ZRender 与构建工具通过 npm 锁文件获取，依赖目录不提交。版本、来源、完整性值和各包声明的许可见 `frontend/package-lock.json`。生产构建提取许可到 `frontend-licenses.txt`，分发静态资源时一并保留。

## MITRE ATT&CK

构建器从 `build_tools/attack-sources.json` 固定提交获取并验证数据。完整数据集和生成目录不提交；对应版权与许可原文附入 `frontend-licenses.txt`。数据许可独立于面板 MIT，见 [固定提交 LICENSE](https://github.com/mitre-attack/attack-stix-data/blob/c2494b29dd268c46a5d0ea0990553e4327cd2253/LICENSE.txt)。

## 外部更新器与规则

PulledPork3 独立安装，本仓库只包含调用接口，不包含其源码、修改、补丁或二进制。第三方规则按来源许可及账户权限获取，不随仓库分发。Snort、Cisco、Talos、MITRE 等名称仅用于说明来源和兼容性，不表示官方关联或认可。

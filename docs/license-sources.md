# 第三方许可核查

查询时间：2026-11-04，Australia/Perth。来源：MCP Search Service。查询条件：项目来源清单固定版本的上游许可与补丁匹配内容。

| 来源 | 查询结果 | 项目处理 |
| --- | --- | --- |
| [Snort 3.12.4.0 COPYING](https://raw.githubusercontent.com/snort3/snort3/3.12.4.0/COPYING) | GPL 第 2 版，文件开头特别说明不授权采用后续 GPL 版本 | 引擎补丁与其中的上游匹配片段按 GPL-2.0-only 保留，保存完整上游声明 |
| [PulledPork3 固定提交 LICENSE](https://raw.githubusercontent.com/shirkdog/pulledpork3/7c4d1f8da433581de0db337487ec639ce42d80b2/LICENSE) 与 [lib/snort.py](https://raw.githubusercontent.com/shirkdog/pulledpork3/7c4d1f8da433581de0db337487ec639ce42d80b2/lib/snort.py) | 许可证为 GPL 第 2 版，补丁包含上游替换目标片段 | 更新器修改与补丁不纳入本仓库，仅保留外部调用接口 |
| [MITRE ATT&CK 固定提交 LICENSE](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/c2494b29dd268c46a5d0ea0990553e4327cd2253/LICENSE.txt) | 允许研究、开发和商业用途的复制，要求保留版权与许可 | 数据在构建时下载、校验并生成；发布产物包含许可，不将数据集提交到仓库 |

初次读取上游默认分支页面仅用于定位，结论以上表固定版本原文为准。GNU GPL 3.0 原文请求超时，未用于判断。

PulledPork3 修改不纳入本仓库。面板独立实现采用 MIT，例外范围见根目录 THIRD_PARTY_NOTICES.md。第三方引擎、更新器、数据集和 npm 依赖各自保留原许可，不能因本仓库许可而重新许可。源码仓库不分发它们的二进制或签名包。

2026-11-07 15:53 UTC，升级时直接读取并校验清单固定归档中的 [Snort 3.13.2.0 COPYING](https://github.com/snort3/snort3/blob/3.13.2.0/COPYING)，与仓库保留的声明逐字节比较（统一换行符后）一致，许可处理保持 GPL-2.0-only。

2026-11-08，运行期签名更新改由 AEGIS 内置 Go 兼容实现提供。该模块根据已有接口与归档格式独立编写，不引入外部 PulledPork3 源码或补丁，也不修改其仓库。已迁移组件的旧 Python 实现已移除，合成兼容对照保留在 `backend/internal/console/testdata`。

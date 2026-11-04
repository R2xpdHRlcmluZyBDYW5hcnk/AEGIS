# Snort 规则源核查

## 内置规则与依赖核查

核查日期：2026-11-04。来源：MCP Search Service 与本项目源码。查询前复用本文及 `docs/snort3-engine.md` 中的规则来源、内置目录与禁用实现记录。

查询条件：`site.docs.snort.org builtin rules inspectors disable ips states suppress flowbits`、`site.docs.snort.org rules flowbits noalert isset dependency`、`site.github.com/snort3/snort3 "builtins.rules"`。直接读取下列官方正文与固定标签 `3.12.4.0` 源码，并定位 `stream_tcp`、`queue_event`、`enabled`、`builtin`、`enable_builtin_rules`、`suppress`、`fpLogEvent`。

查询结果：

- [Snort 3 flowbits 文档](https://docs.snort.org/rules/options/non_payload/flowbits)定义 setter 与 checker 规则：禁用某个必要的 setter 后，依赖其状态的 checker 可能无法匹配。`flowbits:noalert` 仅使该规则不产生告警，不等同于禁用规则。
- [Snort 3 配置文档](https://docs.snort.org/start/configuration)将检查器模块与规则配置分开；`stream_tcp` 提供连接跟踪、流规范化和重组。[Cisco Snort 3 入侵检查说明](https://docs.manage.security.cisco.com/cdfmc/c_intrusion_inspection_intrusion_policies_rules_and_variable_sets_snort3_2.html)说明检查器规则用于产生事件及内联丢包。
- [parse_rule.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/parser/parse_rule.cc)在解析内置规则时拒绝 detection options；真正的内置事件规则不应理解为普通 flowbits setter。[detection_engine.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/detection/detection_engine.cc)中 `inspect` 先执行检查器，再做内容检测；内置事件的 `log_events` 检查规则是否 enabled，未启用则不调用 `fpLogEvent`。据此可区分内置事件规则开关与检查器模块开关。
- [modules.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/main/modules.cc)将 `ips.enable_builtin_rules` 描述为不依赖 stub 启用内置事件；[parser.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/parser/parser.cc)在此开关启用时先调用 `ModuleManager::load_rules`，再读取 `ips.rules` 和 `ips.states`。
- [fp_detect.cc](https://github.com/snort3/snort3/blob/3.12.4.0/src/detection/fp_detect.cc)的 `fpLogEvent` 在事件过滤后仍执行规则动作，内联丢包可以继续发生；告警抑制不应解释为解除阻断。

项目边界：`snort.lua` 显式启用 `ips.enable_builtin_rules`；`snort_rules.apply_policy` 对命中的包内文本规则添加注释；`native_rules.disabled` 对来源限定的组选择器按“Snort 内置”及原生模块组名匹配，`ips-web.write_thresholds` 再输出原生 `ips.states`。由此推导，仅禁用 `builtins snort/lightspd` 包目录组，不能视为已关闭同身份的原生内置事件。此为当前源码行为分析，未核对路由器运行配置或当前 LightSPD 归档内容，也未执行真实流量回放。

## MCP 查询

日期：2026-11-03。

来源：MCP Search Service，限定优先读取 Snort 官方资料。

查询条件：`site.snort.org 422 Unprocessable Entity registered rules downloads snapshot`；`site.snort.org downloads registered snortrules snapshot rules version`。

结果：

- [Snort 官方下载目录](https://www.snort.org/downloads/) 列出 Snort 3.12.4.0 引擎，但规则快照目录含 `31300`、`31200`、`31100` 等项，未在所读结果中列出 `31240`。不能据此把引擎每个修订版本直接拼成可下载的规则快照。
- [官方 Oinkcode 说明](https://www.snort.org/oinkcodes) 说明 Oinkcode 是账户下载密钥；有效订阅获取最新版本，无有效订阅则获取免费规则包。Community 下载不需要 Oinkcode。
- [Snort 官方主页](https://www.snort.org/) 明确所有用户均可访问 Registered 规则集。

HTTP 422 本身不能证明注册码无效或缺少付费订阅。下载流程还需区分请求的规则快照是否存在，以及校验文件或归档响应的实际状态。


## LightSPD 与免费注册权限

核查日期：2026-11-03。来源：MCP Search Service；查询前复用上面的 Oinkcode 记录及 `docs/snort3-engine.md` 的规则更新依据。

补充查询条件：`site.snort.org lightspd subscription registered oinkcode`、`site.blog.snort.org LightSPD registered subscribers`、`site.snort.org "LightSPD" "subscription"`、`site.blog.snort.org "LightSPD" "registered"`。直接读取 Snort 下载页与 PulledPork3 上游 README，核对 LightSPD 的下载凭据及免费权限。

查询结果：

- [PulledPork3 上游 README 的 rulesets 说明](https://github.com/shirkdog/pulledpork3#rulesets)明确 Registered 和 LightSPD 都需要免费的 Snort Oinkcode；不能把 LightSPD 标记为仅限付费订阅。
- [Snort 官方 Oinkcode 说明](https://snort.org/oinkcodes)将 Oinkcode 定义为账户下载 API 密钥；有效订阅取得最新规则，无有效订阅取得免费规则包。Community 无需 Oinkcode。
- [Snort 官方规则集区别](https://snort.org/faq/what-are-the-differences-in-the-rule-sets)说明 Registered 对个人和企业免费，较 Subscriber 延迟 30 天；Subscriber 无此延迟。LightSPD 的打包名称不应与账户的免费或付费权限混为一谈。
- [Snort 官方下载页](https://snort.org/downloads)列出 `Talos_LightSPD.tar.gz`。本次未使用账户凭据执行规则包下载，因此不据此承诺某个账户当前能够成功下载。

## Snort 3 的规则包选择

核查日期：2026-11-03。查询前复用以上账户权限记录。MCP Search Service 补查 `site.blog.snort.org LightSPD rules package Snort 3 rules snapshot`、`site.snort.org "LightSPD" "Snort 3"`。

- [2026-01-20 官方公告](https://blog.snort.org/2026/01/end-of-life-announcement-for-versions.html?m=1)鼓励 Snort 3 用户使用 LightSPD，说明包内包含版本配置和受支持平台的共享对象规则。
- [官方 LightSPD 介绍](https://blog.snort.org/2020/12/soft-release-lightspd-new-rules-package.html?m=0)说明通过 manifest 选择适用引擎版本、平台模块及策略；资源较少的设备可选择 balanced-ips。
- [官方 PulledPork3 介绍](https://blog.snort.org/2021/06/pulledpork-3-rule-updating-for-snort-3.html)说明工具面向 LightSPD，按引擎版本和默认策略处理规则。

本项目当前处理两种包中的文本规则，不因选择 LightSPD 自动部署其中全部 Lua 配置或共享对象。包内共享对象的平台支持必须另行核对 manifest。Registered 已完成本地下载与原生校验；LightSPD 的官方推荐不应替代本项目尚未完成的完整能力验证。

## 整组告警抑制边界

2026-11-03，MCP Search Service 查询 `site.docs.snort.org suppress gid sid configuration`、`site.github.com/shirkdog/pulledpork3 suppression suppress threshold group`，并复用现有上游 README 记录。结果：[Snort GID 说明](https://docs.snort.org/rules/options/general/gid)及 [PulledPork3 README](https://github.com/shirkdog/pulledpork3)分别定义生成器身份与规则包/策略处理；所读文档未确认 PulledPork3 提供按来源和目录的整组告警抑制接口，不能把它当作已有功能。

本地预编译 Snort 的 `--help-config suppress` 列出 gid、sid、track 和 ip，不含组名。控制台需保存来源与组名，再编译为原生抑制条目。同一 GID:SID 在多个来源共享时，运行时仍是同一签名，抑制效果也共享；删除一个组策略必须保留其他组或手动条目对该签名的抑制要求。

# Snort 引擎集成

面板消费 Snort 3 extractor 与 alert_json 日志，通过 Unix 控制套接字查询运行状态及执行规则重载。原生日志由 `ips-event-bridge` 转为持久事件流，Web 查询与规则操作分离。

## 来源和构建边界

可选引擎工具固定 Snort 3.12.4.0、LibDAQ 3.0.28 与 OpenAppID 来源，版本、URL 和 SHA-256 见 `build_tools/snort-sources.json`。归档哈希由项目固定，不等同于上游签名。第三方源码、下载物和二进制在源码树外处理，不提交到面板仓库。

`build_tools/build-snort3-arm64.sh` 在 Linux 交叉构建 Debian 13 ARM64、glibc 2.41 目标；`setup_wsl.py` 为 WSL Debian 安装该工具所需软件包。该路径是可选集成工具，不是面板的通用运行要求。构建和安装会修改指定的工具目录，执行前审阅路径与依赖。

PulledPork3 独立安装。面板仅通过 `IPS_PULLEDPORK` 指定的入口传递配置并读取候选结果，不包含更新器修改，也不负责它的安装或升级。

## 会话标识

`build_tools/patch_snort.py` 给固定版本 Snort 增加 `session_id`，补丁采用上游 GPL-2.0-only，许可见根目录 THIRD_PARTY_NOTICES.md。Linux getrandom 生成进程前缀，原子序号标识逻辑会话，热重载不重置；随机前缀不作数学绝对唯一承诺。

面板保留原生 uid，但只按完整 session_id 关联。没有 ID 的事件独立保留，不用五元组、时间窗或 UID 猜测归属。使用其他 Snort 版本或缺少扩展时，先核对日志字段和原生校验结果。

## 验证

`tests/check_snort_native.py` 提供本地合成流量回放；`build_tools/check_arm64_inline.py` 提供完整 ARM64 内核下的 NFQUEUE 测试。用户态 QEMU 的结果不能替代内核内联测试。引擎、测试虚拟机和规则归档均单独准备，不随源码分发。

官方接口来源：[extractor 字段](https://github.com/snort3/snort3/blob/3.12.4.0/doc/user/extractor.txt)、[LibDAQ NFQ 实现](https://github.com/snort3/libdaq/blob/v3.0.28/modules/nfq/daq_nfq.c)、[Snort 规则动作](https://docs.snort.org/rules/headers/actions)。日志字段以实际引擎输出为准，缺失内容不作推断。

# Snort 原生字段与查询语义

字段依据为固定发布版 [extractor 定义](https://github.com/snort3/snort3/blob/3.13.2.0/doc/user/extractor.txt)、实现源码及合成流量的实际 JSON。实际输出优先于手册中不一致的字段名。

| 原始字段 | 控制台查询 / 展示 |
| --- | --- |
| uid | uid，TEXT 精确匹配 |
| id.orig_h / id.resp_h | src / dst |
| id.orig_p / id.resp_p | sport / dport |
| conn_state / history | state / history；保留原文，不映射成旧状态枚举 |
| orig_pkts / resp_pkts | orig_pkts / resp_pkts，亦可查询 pkts_toserver / pkts_toclient |
| orig_bytes / resp_bytes | orig_bytes / resp_bytes；载荷字节 |
| duration | duration / flow_age |
| server_name | server_name / sni |
| query / answers / qtype_name | query / answers / rrtype |
| uri / status_code | uri / status_code，亦可使用 url / status |
| cipher / curve / validation_status | 同名原生字段 |
| command / arg / user / reply_code | FTP 原生字段 |
| fuid / analyzers / timedout / sha256 | 文件原生字段 |
| action（notice 原文） | 实际引擎处置动作；内部兼容列 reason 保留 reset、drop 等原值，详情显示为引擎处置动作 |
| ips_action / ids_reason | 规则动作与 IDS 模式原因 |

连接状态示例包含 `CLT_TCP_TIME_WAIT SRV_TCP_CLOSED`、`CLT_SRV_UDP_SEEN`。状态为自由文本；不要用旧引擎的 new/established/closed 候选代替原始状态。DNS answers 在当前版本可为字符串，按完整值保存而非拆成字符。HTTP `version` 标准化为 `HTTP/1.1` 等展示值。

notice 中的实际 action 决定是否记录阻断；ips_action 是规则的预期动作。被动回放中的 would_block / would_drop 仍显示为未实际阻断。规则严重度和 MITRE 信息来自本地有效文本规则；未知信息保持空值或未知等级，不根据名称推断。

事件证据中，reset 显示为“重置连接（reset）”，reject 显示为“主动拒绝（reject）”；检测签名、规则动作与引擎处置动作分别展示。未知值、原始 JSON 和查询值保持原文。兼容日志的真实丢包原因仍标为“阻断原因”，连接日志的 reason 仍标为“连接结束原因”。阻断聚合共用动作显示格式，点击后继续按原始 reason 值筛选。

统一事件流中的内部兼容列名仅用于控制台的查询和关联实现，不依赖旧引擎或旧数据库。新安装使用独立事件库。用户可通过详情原始 JSON 查看未经字段改名的 Snort 证据。

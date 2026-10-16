# 网络边沿采集

Guest Agent 的 TCP 探针在 Windows 中优先读取 `GetExtendedTcpTable` 的
`TCP_TABLE_OWNER_PID_ALL` 表。这个 API 一次返回活动 TCP 行、端点、状态和
拥有进程 PID，适合在进程退出前的短轮询中抓住短连接。IPv4 和 IPv6 表都会
被读取，监听行交给监听器探针处理，避免把监听器重复报告成出站连接。

每个 TCP 快照保存 `owningProcessId` 和 `processIdSource`。连接关闭后，关闭
事件继续使用关闭前快照中的 PID，因此不会依赖连接消失后的 `netstat` 查询。
只有扩展 TCP 表或端点 `netstat -ano` 明确给出大于零的 PID 才会写入 owner；
PID 0、权限失败和平台不支持时保留 `processIdSource=unavailable`，不会从
进程名称或服务名称推断样本归属。

Windows API 不可用时探针退回 `IPGlobalProperties.GetActiveTcpConnections()`。
退回路径仍保留端点、状态和打开/关闭边沿，但明确标记
`processIdSource=unavailable-managed-api`。DNS 缓存、hosts、代理和最终
`netstat -ano` 仍由网络状态探针在 AfterRun 采集，作为补充证据，不能替代
运行期间的 TCP owner 表。

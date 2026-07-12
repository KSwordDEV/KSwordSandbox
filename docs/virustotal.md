# VirusTotal（VT）官方 hash-only 信誉后端

Web 后端把 VirusTotal 作为可选信誉富化（reputation enrichment）。集成只使用任务样本的 SHA-256 调用官方 v3 `GET /api/v3/files/{sha256}` file report endpoint：**不上传样本字节、不发 multipart、不提交 URL 扫描、不把样本内容写入 VT 请求**。

## API Key 配置（仅当前进程 / process-only）

- Key 名称：`KSWORDBOX_VIRUSTOTAL_API_KEY`。
- 查找顺序：Process → User → Machine 环境变量。
- Settings 页面和 `POST /api/settings/virustotal` 只写入/清除 **当前 Web Host 进程** 的 Process 环境变量；不会修改 User/Machine 环境变量。
- 清除按钮只移除 Process scope。如果 User/Machine scope 仍有 key，状态仍会显示 configured，并在来源中标明只读来源。
- Web 后端永不把 API key 写入磁盘 / never writes API keys to disk：不得写入仓库文件、config、runtime settings、report、event、cache entry 或 log。
- 需要重启后仍生效时，请在启动 Web Host 之前设置 User/Machine 环境变量，或使用安装器配置入口：

```powershell
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey
```

该命令不应打印 key。不要手工把密钥写进配置文件。

## 不上传样本保证 / No-sample-upload guarantees

代码路径只构造 `HttpMethod.Get` 请求到 `https://www.virustotal.com/api/v3/files/{sha256}`，并仅发送 `x-apikey` 与 JSON accept header。以下行为不属于本集成，不能添加到 hash-only 路径：

- 上传样本字节或 multipart/form-data。
- 调用 VirusTotal upload/scan URL endpoint。
- 把文件名、路径、报告、cache 或 job 输出作为样本内容发送给 VirusTotal。
- 在任务/行为日志（job log / behavior log）中记录 API key、原始错误详情或样本内容。

## 静默状态分类 / quiet-state taxonomy

VT 是外部信誉/健康信息，不等于样本行为。默认只展示，不落盘：

- `GET /api/jobs/{jobId}/virustotal`：仅页面/API 展示（display-only）。
- `GET /api/jobs/{jobId}/virustotal?persist=true` 或 `POST /api/jobs/{jobId}/enrichments/virustotal`：只有 `status=found` 才可写 enrichment event。

静默状态包括：`not_configured`、`not_found`、`rate_limited`、`authentication_failed`、`timeout`、`lookup_failed`、`missing_hash`、`invalid_hash`。

API 同时暴露：

- `quietErrorKind=not_configured|not_found|rate_limit|auth|timeout|lookup_failed|missing_hash|invalid_hash`。
- `quietErrorCategory=configuration|provider_not_found|provider_quota|authentication|network_timeout|lookup_failure|local_input`。
- `isQuietState`、`quietFailureReason`、`quietFailureExplanation`。
- 中文优先字段 `zhStatusText`、`zhStatusDetail`，文案必须说明：只在页面/API 展示，不写任务/行为日志，不阻断沙箱分析。

## 官方摘要字段（official summary fields）

重要响应字段：

- `status` / `verdict`：查询状态和 found report 的信誉判定。
- `lookupMode` / `noSampleUploadGuarantee`：hash-only/no-upload 策略。
- `engineCounts` / `engineCount` / `lastAnalysisStats`：官方引擎统计。
- `lastAnalysisDateUtc`：官方 `last_analysis_date`。
- `reputation`、`communityVotes`、`communityScore`、`communityScoreSource`：官方信誉/社区分数。
- `officialFileObject`：`id`、`type`、`md5`、`sha1`、官方 `sha256`、`sizeBytes`、`fileTypeDescription`、`typeTag`、`magic`、`names`、`tags`、提交/分析/修改/ITW 时间和 `threatClassification`。
- 扁平别名：`officialFileObjectId`、`officialFileObjectType`、`md5`、`sha1`、`officialSha256`、`fileSizeBytes`、`fileTypeDescription`、`typeTag`、`magic`、`names`、`tags`、`suggestedThreatLabel`、`topThreatCategory`、`topThreatName`。
- 摘要字段：`officialSummary`、`zhOfficialSummary`、`officialSummaryFields`。
- 链接：`permalink`、`detectionPermalink`、`officialApiSelfLink`（不含 API key）。
- 缓存元数据：`cacheHit`、`cachedAtUtc`、`cacheExpiresAtUtc`、`cacheAgeSeconds`、`cacheTtlSeconds`。

这些字段是官方 hash 报告元数据，不应作为沙箱行为证据自动高亮；只有显式持久化且 `status=found` 时，才写单个 `enrichment.virustotal.lookup` / `vt.lookup` 事件。

## 缓存行为

缓存只在当前 Web Host 进程内存中，key 为规范化 SHA-256 加非 secret API-key 指纹。它合并同一 hash 的并发查询，避免实时监控页刷新循环反复请求 VirusTotal。

默认 TTL：`found` 24 小时；`not_found` 6 小时；`rate_limited` 优先使用 `Retry-After` 并限制在 30 秒到 30 分钟，否则 5 分钟；`authentication_failed` 5 分钟；`timeout` 45 秒；其他 lookup/HTTP/transport/parse failure 1 分钟。

## 富化持久化 / Enrichment persistence

```http
GET /api/jobs/{jobId}/virustotal
GET /api/jobs/{jobId}/virustotal?persist=true
POST /api/jobs/{jobId}/enrichments/virustotal
```

只有 `status=found` 且调用方显式要求持久化时，才写 provider event。quiet states 只作为静默页面/API 状态：不写 job log / behavior log，不附加 MITRE ATT&CK 映射，不进入主要恶意行为列表，也不阻断沙箱分析。

可持久化事件字段包括：`sha256`、`vtStatus`、`vtVerdict`、`vtMalicious`、`vtSuspicious`、`vtScore`、`vtDetectionCount`、`vtEngineCount`、`vtReputation`、`vtCommunityScore`、`zhStatusText`、`zhStatusDetail`、cache metadata、VirusTotal links，以及 `vtFileSizeBytes`、`vtTypeTag`、`vtSuggestedThreatLabel`、`vtOfficialFileObjectSummary`、`officialSummary`、`zhOfficialSummary` 等 official summary 字段。

## 验证命令

本集成的轻量验证可只运行 Web build（不需要 CSignTool、Hyper-V/live 或 smoke tests）：

```powershell
dotnet build .\src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj
```

不要把真实 API key、查询响应缓存、报告、job 输出或 runtime settings 提交到 git。

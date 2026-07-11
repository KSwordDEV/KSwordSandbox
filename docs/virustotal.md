# VirusTotal（VT）hash-only 信誉后端

Web 后端集成 VirusTotal 作为可选 reputation enrichment。它只用 job sample 的 SHA-256 调用官方
v3 `files/{sha256}` endpoint（端点），**永远不上传样本字节**。

## 配置（configuration）

- API key 查找顺序：`KSWORDBOX_VIRUSTOTAL_API_KEY` 的 Process、User、Machine 环境变量。
- 通过 `POST /api/settings/virustotal` 保存或清除本地 key 时，只更新当前 Web 进程环境变量，并清除
  in-memory lookup cache，让下一次请求使用新设置。
- 设置页仅当前进程有效（process-only）：WebUI 不写 key 文件，Web Host 重启后需要重新输入，
  或在启动前预先设置 User/Machine 环境变量；清除按钮只移除 Process scope，若 User/Machine scope 仍有 key，
  状态会继续显示 configured。
- Web 后端绝不把 key 写入磁盘（never writes API keys to disk）：不得写入仓库文件、runtime settings、report、event、
  cache entry 或 log。
- 缺少 key 时保持低噪音：endpoint 返回 `status=not_configured`，不写 job messages、enrichment events
  或 behavior-rule evidence。

CLI 配置入口：

```powershell
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey
```

该命令不会打印 key。清除本地 key 时使用安装器菜单或相应 clear 参数，不要手工把密钥写进配置文件。

## 低噪音原则（low-noise behavior）

VT 结果是信誉/健康信息，不等于样本行为：

- `GET /api/jobs/{jobId}/virustotal` 默认只用于 UI display（界面展示），不落盘。
- 只有显式 `?persist=true` 或 `POST /api/jobs/{jobId}/enrichments/virustotal` 才尝试保存 enrichment。
- 只有 `status=found` 且调用方显式要求持久化（`?persist=true` 或 enrichment POST）时，才可写入
  `enrichment-events.json` 并参与规则分类；`not_found` 仍是静默信誉状态，不写 job log / behavior log。
- `not_configured`、`rate_limited`、`authentication_failed`、`timeout`、transport failure、parse failure 只返回给
  调用方显示，不转换成 behavior-rule event。
- Live 页将这些结果作为安静状态（quiet states）展示：`not_found`、`rate_limited`、
  `authentication_failed`、`timeout` 不会被渲染成沙箱失败，也不会自动写 job log 或 report enrichment。
- not-found、missing key、rate-limit 不应进入主要恶意行为列表，也不应附加 MITRE ATT&CK 映射。
- API 同时提供稳定 quiet error taxonomy：`quietErrorKind=not_configured`、`auth`、`rate_limit`、`timeout`、
  `not_found`（以及本地输入类 `missing_hash` / `invalid_hash` 和兜底 `lookup_failed`），并用
  `quietErrorCategory` 给 UI/脚本做分组。
- API 提供中文状态字段：`zhStatusText` 是短标签，`zhStatusDetail` 是可直接展示给值守人员的中文解释；
  quiet 状态文字必须说明“只页面/API 展示，不写任务/行为日志，不阻断沙箱分析”。

规则事件使用扁平字段和 compact event name `vt.lookup`，避免依赖嵌套 JSON 谓词。

## 缓存行为（cache behavior）

缓存是每个 Web host process 内存级（in-memory）的，key 为 normalized SHA-256 加非 secret API-key
fingerprint。它会合并同一 hash 的并发 lookup，避免 live monitor 刷新循环反复请求 VirusTotal。

默认 TTL：

- `found`：24 小时。
- `not_found`：6 小时。
- `rate_limited`：优先使用 `Retry-After`，并 clamp 到 30 秒到 30 分钟；否则 5 分钟。
- `authentication_failed`：5 分钟。
- `timeout`：45 秒。
- 其他 lookup / HTTP / transport / parse failure：1 分钟。

API response 带有 UI 可展示的缓存元数据：`cacheHit`、`cachedAtUtc`、`cacheExpiresAtUtc`、
`cacheAgeSeconds`、`cacheTtlSeconds`。缓存只保存在当前 Web 进程内存中；不写 lookup response cache 文件，
也不把 API key 或失败细节写进 job log。

## 实时监控响应字段 / Live monitor response fields

重要展示字段：

- `status`：本地查询状态，如 `found`、`not_found`、`not_configured`、`rate_limited`、
  `authentication_failed`、`timeout`、`lookup_failed`、`missing_hash`、`invalid_hash`。
- `verdict`：已收录报告（found report）的 reputation verdict（`malicious`、`suspicious`、`clean`、`unknown`），
  或 non-found 状态 token。
- `score`：阳性引擎计数（positive engine count），即 `malicious + suspicious`。
- `engineCounts` / `engineCount`：malicious、suspicious、harmless、undetected、timeout、failure、
  type-unsupported、total 的扁平计数。
- `lastAnalysisStats`：保留给现有调用方的原始 VirusTotal stats dictionary。
- `lastAnalysisDateUtc`：官方 `last_analysis_date` 转换出的 UTC 时间。
- `reputation`：官方 file object 的 reputation/community integer（如果响应提供）。
- `communityVotes`：官方 `total_votes.harmless` / `total_votes.malicious`。
- `communityScore` / `communityScoreSource`：优先使用 `reputation`，否则用 community votes 计算
  `harmless - malicious`；字段缺失时保持 null/未提供，不伪造分数。
- `officialFileObject`：从官方 file object 中提取的 operator-safe 元数据，包括 `id`、`type`、`md5`、
  `sha1`、官方 `sha256`、`sizeBytes`、`fileTypeDescription`、`typeTag`、`magic`、`names`、`tags`、
  `firstSubmissionDateUtc`、`lastSubmissionDateUtc`、`lastAnalysisDateUtc`、`lastModificationDateUtc`、
  `firstSeenInTheWildDateUtc` 和 `threatClassification`。
- 同步提供便于前端/脚本读取的扁平字段：`officialFileObjectId`、`officialFileObjectType`、`md5`、`sha1`、
  `officialSha256`、`fileSizeBytes`、`fileTypeDescription`、`typeTag`、`magic`、`names`、`tags`、
  `suggestedThreatLabel`、`topThreatCategory`、`topThreatName`。
- `permalink`：该 hash 的 VirusTotal file overview URL。
- `detectionPermalink`：直接进入检测页的 VirusTotal GUI URL，Live monitor 优先展示它作为主按钮。
- `officialApiSelfLink`：官方 API `data.links.self`，仅作为可复制诊断链接展示，不含 API key。
- `quietErrorKind` / `quietErrorCategory` / `zhStatusText` / `zhStatusDetail`：静默错误分类和中文状态文本。
- `quietFailureReason` / `quietFailureExplanation`：对 missing key、not-found、rate-limit、auth failure、
  timeout、transport/parse failure 的低噪音解释；用于 UI 展示，默认不写 job log。
- 上述 cache metadata（缓存元数据）。

UI 文案应明确“hash-only，不上传样本”。Live monitor 应展示官方引擎统计、最后分析时间、reputation/community
score、可点击 VirusTotal 检测页链接和缓存状态。缺 key、not-found、rate-limit、auth failure、timeout 或其他失败
状态应安静展示在 reputation card / health area，不要作为样本恶意行为高亮，也不要默认写 job log。上传或选择样本后，
VT card 可以与真实 runbook progress、raw events 和 artifact index/download 卡片并列展示，但 VT 状态只是外部信誉补充，
不应阻塞 guest 分析、artifact 回收或报告生成。

## 富化持久化 / Enrichment persistence

默认仅展示、不落盘（display-only）：

```http
GET /api/jobs/{jobId}/virustotal
```

显式保存到 enrichment events：

```http
GET /api/jobs/{jobId}/virustotal?persist=true
```

推荐的新调用方式：

```http
POST /api/jobs/{jobId}/enrichments/virustotal
```

enrichment endpoint（富化端点）执行同样的 hash-only lookup；只有官方已收录 `status=found` 时才写出单个 provider event。
面向规则的
type 为 `enrichment.virustotal.lookup`，event data 中 compact name 为 `vt.lookup`。扁平字段包括：
`sha256`、`vtStatus`、`vtVerdict`、`vtMalicious`、`vtSuspicious`、`vtScore`、
`vtDetectionCount`、`vtEngineCount`、`vtReputation`、`vtCommunityScore`、
`vtCommunityHarmlessVotes`、`vtCommunityMaliciousVotes`、`zhStatusText`、`zhStatusDetail`、cache metadata、
VirusTotal permalink，以及 compact official file-object fields（如 `vtFileSizeBytes`、`vtTypeTag`、
`vtSuggestedThreatLabel`、`vtFirstSubmissionDateUtc`）。

响应包含 `canPersistEnrichmentEvent` 和 `persistedToEnrichmentEvents`，
调用方可据此解释为什么某些 quiet states 没有落盘。

## 验证命令

```powershell
# 缺 key/规则低噪音/报告信誉区契约（contract）。
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj --no-build -- `
  --scenario behavior.rules-virustotal-quality `
  --scenario report.health-reputation.contract `
  --scenario rules.schema-collection-health.guard

# 快速质量门，默认不联网、不启动 VM。
.\scripts\Test-QualityGates.ps1
```

不要把真实 API key、查询响应缓存、报告、job 输出或 runtime settings 提交到 git。

using System.Globalization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;

namespace KSword.Sandbox.Core.Jobs;

public sealed partial class SandboxJobService
{
    private static readonly ArtifactImportExpectation[] ArtifactImportExpectations =
    [
        new(
            "dropped-files",
            ArtifactKind.DroppedFile,
            "掉落文件",
            "dropped files",
            "artifacts/dropped-files",
            "请确认已启用掉落文件收集，样本在工作目录内产生了新文件，并且收集阶段成功复制到 artifacts/dropped-files。",
            config => config.CollectDroppedFiles),
        new(
            "screenshots",
            ArtifactKind.Screenshot,
            "截图",
            "screenshots",
            "screenshots",
            "请确认已启用截图采集，来宾桌面会话可用，并且 GDI/权限/输出路径未阻止截图写出。",
            config => config.CaptureScreenshots),
        new(
            "memory-dumps",
            ArtifactKind.MemoryDump,
            "内存转储",
            "memory dumps",
            "memory-dumps",
            "请确认已启用内存转储，目标进程仍可见，且来宾权限允许 MiniDumpWriteDump 写出转储。",
            config => config.CaptureMemoryDumps),
        new(
            "packet-captures",
            ArtifactKind.PacketCapture,
            "抓包",
            "packet captures",
            "packet-captures",
            "请确认已启用抓包，pktmon 可用且转换成功；也可将已有 .pcap/.pcapng 放入 packet-captures 供 Host 导入。",
            config => config.CapturePacketCapture)
    ];

    /// <summary>
    /// Builds host-side artifact import and health events for reports.
    /// Inputs are the planned artifact configuration, host job root, optional
    /// events path, host artifact index, and current events; processing emits
    /// one metadata-rich import row per downloadable sensitive artifact plus
    /// collection-health diagnostics for requested/declared lanes with no
    /// downloadable files; the method returns non-behavior telemetry rows.
    /// </summary>
    private static List<SandboxEvent> BuildHostArtifactImportEvents(
        ArtifactCollectionConfig artifactCollection,
        string jobRoot,
        string? guestEventsPath,
        HostArtifactIndex artifactIndex,
        IReadOnlyList<SandboxEvent> currentEvents)
    {
        var generated = new List<SandboxEvent>();
        var eventKeys = currentEvents.Select(EventKey).ToHashSet(StringComparer.Ordinal);
        AddGeneratedEvent(generated, eventKeys, CreateHostArtifactImportSummaryEvent(artifactIndex, jobRoot, guestEventsPath));

        foreach (var artifact in artifactIndex.Artifacts
            .Where(IsSensitiveHostImportArtifact)
            .OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase))
        {
            AddGeneratedEvent(generated, eventKeys, CreateHostArtifactImportedEvent(artifact, jobRoot, guestEventsPath));
        }

        foreach (var expectation in ArtifactImportExpectations)
        {
            var artifactCount = artifactIndex.Artifacts.Count(artifact =>
                artifact.Kind == expectation.Kind ||
                string.Equals(artifact.CollectionName, expectation.CollectionName, StringComparison.OrdinalIgnoreCase));
            if (artifactCount > 0)
            {
                continue;
            }

            var requested = expectation.IsRequested(artifactCollection);
            var collection = artifactIndex.Collections.FirstOrDefault(candidate =>
                string.Equals(candidate.Name, expectation.CollectionName, StringComparison.OrdinalIgnoreCase));
            var sourceEvent = FindCollectionSourceEvent(currentEvents, expectation.CollectionName);
            var hasCollectionSignal = collection is not null || sourceEvent is not null;
            if (!requested && !hasCollectionSignal)
            {
                continue;
            }

            var status = FirstNonEmpty(
                collection?.Status,
                ReadNullableEventData(sourceEvent, "status"),
                ReadNullableEventData(sourceEvent, "captureState"),
                requested ? "missing" : "disabled");
            var reason = FirstNonEmpty(
                collection?.Reason,
                ReadNullableEventData(sourceEvent, "reason"),
                requested ? "noDownloadableArtifacts" : "notRequested");

            if (!requested &&
                IsDisabledStatus(status) &&
                IsNotRequestedReason(reason))
            {
                continue;
            }

            AddGeneratedEvent(
                generated,
                eventKeys,
                CreateCollectionHealthEvent(
                    expectation,
                    artifactCount,
                    requested,
                    status,
                    reason,
                    collection,
                    sourceEvent,
                    jobRoot,
                    guestEventsPath));
        }

        foreach (var collection in artifactIndex.Collections
            .Where(HasRejectionDiagnostics)
            .OrderBy(collection => collection.Name, StringComparer.OrdinalIgnoreCase))
        {
            AddGeneratedEvent(generated, eventKeys, CreateArtifactImportRejectedEvent(collection, jobRoot, guestEventsPath));
        }

        return generated;
    }

    private static SandboxEvent CreateHostArtifactImportSummaryEvent(
        HostArtifactIndex artifactIndex,
        string jobRoot,
        string? guestEventsPath)
    {
        var sensitiveImportCount = artifactIndex.Artifacts.Count(IsSensitiveHostImportArtifact);
        var duplicateGroupCount = artifactIndex.Artifacts
            .Select(artifact => MetadataValue(artifact.Metadata, "duplicateGroupId"))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var rejectedCollections = artifactIndex.Collections
            .Where(HasRejectionDiagnostics)
            .Select(collection => collection.Name)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var collectionNames = artifactIndex.Collections
            .Select(collection => collection.Name)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var collectionStats = ArtifactImportExpectations
            .Select(expectation => new ArtifactImportCollectionStat(
                expectation.CollectionName,
                expectation.Kind,
                expectation.ChineseName,
                CountArtifactsForExpectation(artifactIndex.Artifacts, expectation),
                SumArtifactBytesForExpectation(artifactIndex.Artifacts, expectation),
                SelectorsForExpectation(artifactIndex.Artifacts, expectation)))
            .ToList();
        var readyCollectionNames = collectionStats
            .Where(stat => stat.Count > 0)
            .Select(stat => stat.CollectionName)
            .ToList();
        var missingCollectionNames = collectionStats
            .Where(stat => stat.Count == 0)
            .Select(stat => stat.CollectionName)
            .ToList();
        var evidenceMatrix = string.Join(
            ";",
            collectionStats.Select(stat =>
                $"{stat.CollectionName}={stat.Count.ToString(CultureInfo.InvariantCulture)}:{(stat.Count > 0 ? "ready" : "missing")}:{stat.TotalBytes.ToString(CultureInfo.InvariantCulture)}"));
        var evidenceMatrixZh = string.Join(
            "，",
            collectionStats.Select(stat => $"{stat.ChineseName}={stat.Count.ToString(CultureInfo.InvariantCulture)}"));
        var primarySelectors = collectionStats
            .SelectMany(stat => stat.Selectors.Select(selector => $"{stat.CollectionName}:{selector}"))
            .Take(16)
            .ToList();

        return new SandboxEvent
        {
            EventType = "artifact.import_summary",
            Source = "host",
            Path = jobRoot,
            Data =
            {
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["behaviorScope"] = "artifact-import-summary",
                ["notSampleBehavior"] = "true",
                ["collectionNoise"] = "true",
                ["hostImportSelfNoise"] = "true",
                ["selfNoisePolicy"] = "host-artifact-index-metadata-not-sample-behavior",
                ["sampleBehaviorImpact"] = "metadata-only-do-not-score",
                ["sampleEvidenceArtifact"] = (sensitiveImportCount > 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["evidenceDerivedFromSample"] = (sensitiveImportCount > 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["importMode"] = "host-artifact-index",
                ["downloadPolicy"] = artifactIndex.DownloadPolicy,
                ["importedSensitiveArtifactCount"] = sensitiveImportCount.ToString(CultureInfo.InvariantCulture),
                ["sensitiveArtifactCount"] = artifactIndex.SensitiveArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["downloadableArtifactCount"] = artifactIndex.DownloadableArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["artifactCount"] = artifactIndex.ArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["collectionCount"] = artifactIndex.CollectionCount.ToString(CultureInfo.InvariantCulture),
                ["rootPathPolicy"] = artifactIndex.RootPathPolicy,
                ["hostImport"] = "true",
                ["duplicateArtifactCount"] = artifactIndex.DuplicateArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["duplicateGroupCount"] = duplicateGroupCount.ToString(CultureInfo.InvariantCulture),
                ["rejectedArtifactCount"] = artifactIndex.RejectedArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["hasDuplicateArtifacts"] = (artifactIndex.DuplicateArtifactCount > 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["hasRejectedArtifacts"] = (artifactIndex.RejectedArtifactCount > 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["downloadSecurityPolicy"] = "server-indexed-relative-selector",
                ["downloadRejectionPolicy"] = "reject-empty-absolute-traversal-unindexed-missing",
                ["selectorAuthority"] = "host-artifact-index",
                ["selectorSafety"] = "normalized-relative-indexed",
                ["collectionNames"] = string.Join(",", collectionNames),
                ["artifactEvidenceMatrix"] = evidenceMatrix,
                ["artifactEvidenceSummaryZh"] = evidenceMatrixZh,
                ["artifactEvidenceCollectionsReady"] = string.Join(",", readyCollectionNames),
                ["artifactEvidenceCollectionsMissing"] = string.Join(",", missingCollectionNames),
                ["primaryArtifactSelectors"] = string.Join(",", primarySelectors),
                ["hasDroppedFileArtifacts"] = HasArtifactsForKind(collectionStats, ArtifactKind.DroppedFile),
                ["hasScreenshotArtifacts"] = HasArtifactsForKind(collectionStats, ArtifactKind.Screenshot),
                ["hasMemoryDumpArtifacts"] = HasArtifactsForKind(collectionStats, ArtifactKind.MemoryDump),
                ["hasPacketCaptureArtifacts"] = HasArtifactsForKind(collectionStats, ArtifactKind.PacketCapture),
                ["droppedFileArtifactCount"] = CountForKind(collectionStats, ArtifactKind.DroppedFile),
                ["screenshotArtifactCount"] = CountForKind(collectionStats, ArtifactKind.Screenshot),
                ["memoryDumpArtifactCount"] = CountForKind(collectionStats, ArtifactKind.MemoryDump),
                ["packetCaptureArtifactCount"] = CountForKind(collectionStats, ArtifactKind.PacketCapture),
                ["droppedFileBytes"] = BytesForKind(collectionStats, ArtifactKind.DroppedFile),
                ["screenshotBytes"] = BytesForKind(collectionStats, ArtifactKind.Screenshot),
                ["memoryDumpBytes"] = BytesForKind(collectionStats, ArtifactKind.MemoryDump),
                ["packetCaptureBytes"] = BytesForKind(collectionStats, ArtifactKind.PacketCapture),
                ["rejectionDiagnosticCollections"] = string.Join(",", rejectedCollections),
                ["sourceEventType"] = "host.artifact.index",
                ["sourceEventPath"] = FirstNonEmpty(guestEventsPath, jobRoot),
                ["indexRoot"] = jobRoot,
                ["zhMessage"] = $"Host 产物导入完成：{sensitiveImportCount.ToString(CultureInfo.InvariantCulture)} 个敏感证据产物可用于报告下载；{evidenceMatrixZh}。",
                ["zhHint"] = "这是 artifact-index 导入摘要，用于报告状态、下载和诊断；Host 导入动作本身不作为样本行为判定。artifactEvidenceMatrix 以 collection=count:state:bytes 形式概览 dropped files、截图、内存转储和抓包证据。"
            }
        };
    }

    private static SandboxEvent CreateArtifactImportRejectedEvent(
        ArtifactCollectionDescriptor collection,
        string jobRoot,
        string? guestEventsPath)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["collectionName"] = collection.Name,
            ["artifactKind"] = collection.Kind.ToString(),
            ["sourceArtifactKind"] = collection.Kind.ToString(),
            ["artifactRejected"] = "true",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["behaviorScope"] = "artifact-import-rejection",
            ["notSampleBehavior"] = "true",
            ["collectionNoise"] = "true",
            ["hostImportSelfNoise"] = "true",
            ["selfNoisePolicy"] = "rejected-artifact-selector-diagnostic-not-sample-behavior",
            ["sampleBehaviorImpact"] = "metadata-only-do-not-score",
            ["sampleEvidenceArtifact"] = "false",
            ["evidenceDerivedFromSample"] = "false",
            ["hostImport"] = "true",
            ["importMode"] = "host-artifact-index",
            ["sourceEventType"] = "host.artifact.index",
            ["sourceEventPath"] = FirstNonEmpty(guestEventsPath, jobRoot),
            ["indexRoot"] = jobRoot,
            ["diagnosticCategory"] = "artifact-import",
            ["healthSeverity"] = "warning",
            ["downloadSecurityPolicy"] = FirstNonEmpty(MetadataValue(collection.Metadata, "downloadSecurityPolicy"), "server-indexed-relative-selector"),
            ["downloadRejectionPolicy"] = FirstNonEmpty(MetadataValue(collection.Metadata, "downloadRejectionPolicy"), "reject-empty-absolute-traversal-unindexed-missing"),
            ["selectorAuthority"] = FirstNonEmpty(MetadataValue(collection.Metadata, "selectorAuthority"), "host-artifact-index"),
            ["selectorSafety"] = FirstNonEmpty(MetadataValue(collection.Metadata, "selectorSafety"), "rejected-or-unavailable"),
            ["rejectionDiagnosticsAvailable"] = FirstNonEmpty(MetadataValue(collection.Metadata, "rejectionDiagnosticsAvailable"), "true"),
            ["rejectedArtifactCount"] = FirstNonEmpty(MetadataValue(collection.Metadata, "rejectedArtifactCount"), "0"),
            ["artifactRejectionReasons"] = FirstNonEmpty(MetadataValue(collection.Metadata, "artifactRejectionReasons"), collection.Reason),
            ["lastRejectedArtifactReason"] = FirstNonEmpty(MetadataValue(collection.Metadata, "lastRejectedArtifactReason"), collection.Reason),
            ["lastRejectedArtifactSelector"] = FirstNonEmpty(MetadataValue(collection.Metadata, "lastRejectedArtifactSelector"), collection.ImportPath, collection.RelativePath),
            ["zhMessage"] = $"Host 已拒绝 {collection.Name} collection 中的不安全、缺失或重复 artifact 引用。",
            ["zhHint"] = FirstNonEmpty(
                MetadataValue(collection.Metadata, "zhRejectionHint"),
                "只有 job 输出目录下已索引且存在的相对 selector 可以下载；被拒绝引用仅用于操作者诊断。")
        };

        AddIfNotEmpty(data, "lastRejectedArtifactName", MetadataValue(collection.Metadata, "lastRejectedArtifactName"));
        AddIfNotEmpty(data, "lastRejectedArtifactKind", MetadataValue(collection.Metadata, "lastRejectedArtifactKind"));
        AddIfNotEmpty(data, "lastRejectedGuestRoot", MetadataValue(collection.Metadata, "lastRejectedGuestRoot"));
        AddIfNotEmpty(data, "artifactRejectionsJson", MetadataValue(collection.Metadata, "artifactRejectionsJson"));

        return new SandboxEvent
        {
            EventType = "artifact.import_rejected",
            Source = "host",
            Path = FirstNonEmpty(guestEventsPath, jobRoot),
            Data = data
        };
    }

    private static bool IsSensitiveHostImportArtifact(ArtifactDescriptor artifact)
    {
        return artifact.Kind is ArtifactKind.DroppedFile or ArtifactKind.Screenshot or ArtifactKind.MemoryDump or ArtifactKind.PacketCapture ||
            ArtifactImportExpectations.Any(expectation =>
                string.Equals(artifact.CollectionName, expectation.CollectionName, StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasRejectionDiagnostics(ArtifactCollectionDescriptor collection)
    {
        return string.Equals(MetadataValue(collection.Metadata, "rejectionDiagnosticsAvailable"), "true", StringComparison.OrdinalIgnoreCase) ||
            TryReadPositiveInt(MetadataValue(collection.Metadata, "rejectedArtifactCount"), out _);
    }

    private static SandboxEvent CreateHostArtifactImportedEvent(
        ArtifactDescriptor artifact,
        string jobRoot,
        string? guestEventsPath)
    {
        var sourceEventType = FirstNonEmpty(
            MetadataValue(artifact.Metadata, "sourceEventType"),
            MetadataValue(artifact.Metadata, "lastEventType"),
            MetadataValue(artifact.Metadata, "guestManifestEventType"),
            "host.filesystem.scan");
        var sourceEventPath = FirstNonEmpty(
            MetadataValue(artifact.Metadata, "sourceEventPath"),
            MetadataValue(artifact.Metadata, "lastEventPath"),
            MetadataValue(artifact.Metadata, "sourceEventsPath"),
            guestEventsPath,
            artifact.FullPath);

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["artifactKind"] = artifact.Kind.ToString(),
            ["sourceArtifactKind"] = artifact.Kind.ToString(),
            ["artifactKindZh"] = ChineseKindName(artifact.Kind),
            ["sourceArtifactKindZh"] = ChineseKindName(artifact.Kind),
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["behaviorScope"] = "artifact-import-metadata",
            ["notSampleBehavior"] = "true",
            ["collectionNoise"] = "true",
            ["hostImportSelfNoise"] = "true",
            ["selfNoisePolicy"] = "artifact-host-import-row-not-sample-behavior",
            ["sampleBehaviorImpact"] = "metadata-only-do-not-score",
            ["sampleEvidenceArtifact"] = IsSensitiveHostImportArtifact(artifact).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["evidenceDerivedFromSample"] = IsSensitiveHostImportArtifact(artifact).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["sourceEventType"] = sourceEventType,
            ["downloadSelector"] = artifact.RelativePath,
            ["downloadSafeLink"] = artifact.SafeLink,
            ["safeRelativeSelector"] = artifact.RelativePath,
            ["downloadFileName"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadFileName"), artifact.Name),
            ["downloadContentType"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadContentType"), artifact.MimeType),
            ["downloadSecurityPolicy"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadSecurityPolicy"), "server-indexed-relative-selector"),
            ["downloadRejectionPolicy"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadRejectionPolicy"), "reject-empty-absolute-traversal-unindexed-missing"),
            ["downloadIndexPolicy"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadIndexPolicy"), "artifact-index-relative-selectors-only"),
            ["selectorAuthority"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "selectorAuthority"), "host-artifact-index"),
            ["selectorSafety"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "selectorSafety"), "normalized-relative-indexed"),
            ["isDownloadable"] = FirstNonEmpty(MetadataValue(artifact.Metadata, "isDownloadable"), "true"),
            ["sourceEventPath"] = sourceEventPath,
            ["artifactCategory"] = artifact.Category,
            ["artifactRelativePath"] = artifact.RelativePath,
            ["sourceArtifactRelativePath"] = artifact.RelativePath,
            ["safeLink"] = artifact.SafeLink,
            ["importPath"] = artifact.ImportPath,
            ["fullPath"] = artifact.FullPath,
            ["collectionName"] = artifact.CollectionName,
            ["evidenceRole"] = artifact.EvidenceRole,
            ["mimeType"] = artifact.MimeType,
            ["sizeBytes"] = artifact.SizeBytes.ToString(CultureInfo.InvariantCulture),
            ["sourceArtifactSizeBytes"] = artifact.SizeBytes.ToString(CultureInfo.InvariantCulture),
            ["artifactSizeBytes"] = artifact.SizeBytes.ToString(CultureInfo.InvariantCulture),
            ["hostImport"] = "true",
            ["importMode"] = "host-artifact-index",
            ["indexRoot"] = jobRoot,
            ["zhMessage"] = $"Host 已索引可下载产物：{ChineseKindName(artifact.Kind)}。",
            ["zhHint"] = "这是 Host 产物导入元数据，用于下载和溯源；产物可作为样本证据，但 Host 导入动作本身不作为样本行为判定。",
            ["downloadHintZh"] = "仅允许使用 Host artifact-index.json 中的相对 downloadSelector 下载；拒绝绝对路径、路径穿越、未索引或已缺失文件。"
        };

        AddIfNotEmpty(data, "sha256", artifact.Sha256);
        AddIfNotEmpty(data, "artifactSha256", artifact.Sha256);
        AddIfNotEmpty(data, "sourceArtifactSha256", artifact.Sha256);
        AddIfNotEmpty(data, "hash.sha256", artifact.Hashes.TryGetValue("sha256", out var hash) ? hash : artifact.Sha256);
        AddIfNotEmpty(data, "guestPath", artifact.GuestPath);
        AddIfNotEmpty(data, "sourceEventSource", MetadataValue(artifact.Metadata, "sourceEventSource"));
        AddIfNotEmpty(data, "sourceEventsPath", MetadataValue(artifact.Metadata, "sourceEventsPath"));
        AddIfNotEmpty(data, "processId", MetadataValue(artifact.Metadata, "processId"));
        AddIfNotEmpty(data, "parentProcessId", MetadataValue(artifact.Metadata, "parentProcessId"));
        AddIfNotEmpty(data, "rootProcessId", MetadataValue(artifact.Metadata, "rootProcessId", "rootPid", "processRootId"));
        AddIfNotEmpty(data, "treeLineage", MetadataValue(artifact.Metadata, "treeLineage", "processTreeLineage", "lineage"));
        AddIfNotEmpty(data, "processName", MetadataValue(artifact.Metadata, "processName"));
        AddIfNotEmpty(data, "commandLine", MetadataValue(artifact.Metadata, "commandLine"));
        AddIfNotEmpty(data, "duplicateGroupKey", MetadataValue(artifact.Metadata, "duplicateGroupKey"));
        AddIfNotEmpty(data, "duplicateGroupId", MetadataValue(artifact.Metadata, "duplicateGroupId"));
        AddIfNotEmpty(data, "duplicateGroupCount", MetadataValue(artifact.Metadata, "duplicateGroupCount"));
        AddIfNotEmpty(data, "duplicateOrdinal", MetadataValue(artifact.Metadata, "duplicateOrdinal"));
        AddIfNotEmpty(data, "duplicateRole", MetadataValue(artifact.Metadata, "duplicateRole"));
        AddIfNotEmpty(data, "isDuplicate", MetadataValue(artifact.Metadata, "isDuplicate"));
        AddIfNotEmpty(data, "duplicatePrimarySelector", MetadataValue(artifact.Metadata, "duplicatePrimarySelector"));
        AddIfNotEmpty(data, "duplicatePrimarySafeLink", MetadataValue(artifact.Metadata, "duplicatePrimarySafeLink"));
        AddIfNotEmpty(data, "duplicateOfArtifactRelativePath", MetadataValue(artifact.Metadata, "duplicateOfArtifactRelativePath"));
        AddIfNotEmpty(data, "duplicateGroupMemberSelectors", MetadataValue(artifact.Metadata, "duplicateGroupMemberSelectors"));
        AddIfNotEmpty(data, "duplicateGroupMemberSelectorsJson", MetadataValue(artifact.Metadata, "duplicateGroupMemberSelectorsJson"));
        AddIfNotEmpty(data, "previewLabel", MetadataValue(artifact.Metadata, "previewLabel"));
        AddIfNotEmpty(data, "previewLabelZh", MetadataValue(artifact.Metadata, "previewLabelZh"));
        AddIfNotEmpty(data, "sizeDisplay", MetadataValue(artifact.Metadata, "sizeDisplay"));
        AddIfNotEmpty(data, "sha256Short", MetadataValue(artifact.Metadata, "sha256Short"));
        AddIfNotEmpty(data, "apiMetadataVersion", MetadataValue(artifact.Metadata, "apiMetadataVersion"));
        AddIfNotEmpty(data, "selectorEncoding", MetadataValue(artifact.Metadata, "selectorEncoding"));
        AddIfNotEmpty(data, "selectorFields", MetadataValue(artifact.Metadata, "selectorFields"));

        return new SandboxEvent
        {
            EventType = "artifact.host_imported",
            Source = "host",
            Path = artifact.FullPath,
            Data = data
        };
    }

    private static SandboxEvent CreateCollectionHealthEvent(
        ArtifactImportExpectation expectation,
        int artifactCount,
        bool requested,
        string status,
        string reason,
        ArtifactCollectionDescriptor? collection,
        SandboxEvent? sourceEvent,
        string jobRoot,
        string? guestEventsPath)
    {
        var normalizedStatus = string.IsNullOrWhiteSpace(status) ? "missing" : status;
        var normalizedReason = string.IsNullOrWhiteSpace(reason) ? "noDownloadableArtifacts" : reason;
        var sourceEventType = FirstNonEmpty(sourceEvent?.EventType, collection?.Metadata.GetValueOrDefault("lastEventType"), "host.artifact.collection.scan");
        var sourceEventPath = FirstNonEmpty(sourceEvent?.Path, collection?.Metadata.GetValueOrDefault("lastEventPath"), guestEventsPath, jobRoot);
        var severity = IsDisabledStatus(normalizedStatus) ? "info" : "warning";
        var zhMessage = $"Host 未发现可下载的{expectation.ChineseName}产物；这是采集健康诊断，不代表样本行为。";
        if (IsDisabledStatus(normalizedStatus))
        {
            zhMessage = $"{expectation.ChineseName}采集未启用或未请求；这是采集健康状态，不代表样本行为。";
        }

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["collectionName"] = expectation.CollectionName,
            ["artifactKind"] = expectation.Kind.ToString(),
            ["sourceArtifactKind"] = expectation.Kind.ToString(),
            ["artifactMissing"] = "true",
            ["healthStatus"] = "collection-health",
            ["sourceEventType"] = sourceEventType,
            ["artifactKindZh"] = expectation.ChineseName,
            ["sourceArtifactKindZh"] = expectation.ChineseName,
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["behaviorScope"] = "collection-health",
            ["notSampleBehavior"] = "true",
            ["collectionNoise"] = "true",
            ["hostImportSelfNoise"] = "true",
            ["selfNoisePolicy"] = "collection-health-diagnostic-not-sample-behavior",
            ["sampleBehaviorImpact"] = "metadata-only-do-not-score",
            ["sampleEvidenceArtifact"] = "false",
            ["evidenceDerivedFromSample"] = "false",
            ["sourceEventPath"] = sourceEventPath,
            ["artifactCount"] = artifactCount.ToString(CultureInfo.InvariantCulture),
            ["expectedRelativePath"] = expectation.DefaultRelativePath,
            ["requested"] = requested.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["status"] = normalizedStatus,
            ["reason"] = normalizedReason,
            ["healthSeverity"] = severity,
            ["diagnosticCategory"] = "artifact-import",
            ["hostImport"] = "true",
            ["importMode"] = "host-artifact-index",
            ["indexRoot"] = jobRoot,
            ["zhMessage"] = zhMessage,
            ["zhHint"] = expectation.ChineseHint
        };

        AddIfNotEmpty(data, "guestManifestStatus", collection?.Metadata.GetValueOrDefault("guestManifestStatus"));
        AddIfNotEmpty(data, "guestManifestReason", collection?.Metadata.GetValueOrDefault("guestManifestReason"));
        AddIfNotEmpty(data, "diagnosticStage", ReadNullableEventData(sourceEvent, "diagnosticStage"));
        AddIfNotEmpty(data, "exceptionType", ReadNullableEventData(sourceEvent, "exceptionType"));
        AddIfNotEmpty(data, "win32Error", ReadNullableEventData(sourceEvent, "win32Error"));
        AddIfNotEmpty(data, "commandMessage", ReadNullableEventData(sourceEvent, "commandMessage"));

        return new SandboxEvent
        {
            EventType = "collection.health",
            Source = "host",
            Path = sourceEventPath,
            Data = data
        };
    }

    private static SandboxEvent? FindCollectionSourceEvent(
        IEnumerable<SandboxEvent> events,
        string collectionName)
    {
        return events
            .Where(evt =>
                string.Equals(ReadNullableEventData(evt, "collectionName"), collectionName, StringComparison.OrdinalIgnoreCase) ||
                EventTypeMatchesCollection(evt.EventType, collectionName))
            .OrderBy(evt => CaptureStateRank(ReadNullableEventData(evt, "captureState"), evt.EventType))
            .ThenBy(evt => evt.Timestamp)
            .LastOrDefault();
    }

    private static bool EventTypeMatchesCollection(string eventType, string collectionName)
    {
        return collectionName switch
        {
            "dropped-files" => eventType.StartsWith("artifact.dropped_file.", StringComparison.OrdinalIgnoreCase),
            "screenshots" => eventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase),
            "memory-dumps" => eventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase),
            "packet-captures" => eventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) ||
                eventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static int CaptureStateRank(string state, string eventType)
    {
        var normalized = FirstNonEmpty(state, eventType);
        if (normalized.Contains("failed", StringComparison.OrdinalIgnoreCase))
        {
            return 5;
        }

        if (normalized.Contains("skipped", StringComparison.OrdinalIgnoreCase))
        {
            return 4;
        }

        if (normalized.Contains("disabled", StringComparison.OrdinalIgnoreCase))
        {
            return 3;
        }

        if (normalized.Contains("captured", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("copied", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        return 1;
    }

    private static void AddGeneratedEvent(
        List<SandboxEvent> generated,
        HashSet<string> eventKeys,
        SandboxEvent evt)
    {
        var normalized = NormalizeEvent(evt);
        if (eventKeys.Add(EventKey(normalized)))
        {
            generated.Add(normalized);
        }
    }

    private static bool IsDisabledStatus(string status)
    {
        return status.Equals("disabled", StringComparison.OrdinalIgnoreCase) ||
            status.Equals("not-requested", StringComparison.OrdinalIgnoreCase) ||
            status.Equals("notRequested", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsNotRequestedReason(string reason)
    {
        return reason.Contains("notRequested", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("not-requested", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("NotRequested", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryReadPositiveInt(string? value, out int count)
    {
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out count) && count > 0;
    }

    private static int CountArtifactsForExpectation(IEnumerable<ArtifactDescriptor> artifacts, ArtifactImportExpectation expectation)
    {
        return artifacts.Count(artifact =>
            artifact.Kind == expectation.Kind ||
            string.Equals(artifact.CollectionName, expectation.CollectionName, StringComparison.OrdinalIgnoreCase));
    }

    private static long SumArtifactBytesForExpectation(IEnumerable<ArtifactDescriptor> artifacts, ArtifactImportExpectation expectation)
    {
        return artifacts
            .Where(artifact =>
                artifact.Kind == expectation.Kind ||
                string.Equals(artifact.CollectionName, expectation.CollectionName, StringComparison.OrdinalIgnoreCase))
            .Sum(artifact => Math.Max(0, artifact.SizeBytes));
    }

    private static IReadOnlyList<string> SelectorsForExpectation(IEnumerable<ArtifactDescriptor> artifacts, ArtifactImportExpectation expectation)
    {
        return artifacts
            .Where(artifact =>
                artifact.Kind == expectation.Kind ||
                string.Equals(artifact.CollectionName, expectation.CollectionName, StringComparison.OrdinalIgnoreCase))
            .Select(artifact => FirstNonEmpty(artifact.RelativePath, artifact.SafeLink, artifact.ImportPath))
            .Where(selector => !string.IsNullOrWhiteSpace(selector))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(selector => selector, StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
    }

    private static string HasArtifactsForKind(IEnumerable<ArtifactImportCollectionStat> stats, ArtifactKind kind)
    {
        return (stats.Any(stat => stat.Kind == kind && stat.Count > 0))
            .ToString(CultureInfo.InvariantCulture)
            .ToLowerInvariant();
    }

    private static string CountForKind(IEnumerable<ArtifactImportCollectionStat> stats, ArtifactKind kind)
    {
        return stats
            .Where(stat => stat.Kind == kind)
            .Sum(stat => stat.Count)
            .ToString(CultureInfo.InvariantCulture);
    }

    private static string BytesForKind(IEnumerable<ArtifactImportCollectionStat> stats, ArtifactKind kind)
    {
        return stats
            .Where(stat => stat.Kind == kind)
            .Sum(stat => stat.TotalBytes)
            .ToString(CultureInfo.InvariantCulture);
    }

    private static string ChineseKindName(ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.DroppedFile => "掉落文件",
            ArtifactKind.Screenshot => "截图",
            ArtifactKind.MemoryDump => "内存转储",
            ArtifactKind.PacketCapture => "抓包",
            _ => "产物"
        };
    }

    private static string ReadNullableEventData(SandboxEvent? evt, string key)
    {
        return evt is not null && evt.Data.TryGetValue(key, out var value) ? value : string.Empty;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string? MetadataValue(IDictionary<string, string>? metadata, params string[] keys)
    {
        if (metadata is null)
        {
            return null;
        }

        foreach (var key in keys)
        {
            if (metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    private sealed record ArtifactImportExpectation(
        string CollectionName,
        ArtifactKind Kind,
        string ChineseName,
        string EnglishName,
        string DefaultRelativePath,
        string ChineseHint,
        Func<ArtifactCollectionConfig, bool> IsRequested);

    private sealed record ArtifactImportCollectionStat(
        string CollectionName,
        ArtifactKind Kind,
        string ChineseName,
        int Count,
        long TotalBytes,
        IReadOnlyList<string> Selectors);
}

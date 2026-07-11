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

        return generated;
    }

    private static bool IsSensitiveHostImportArtifact(ArtifactDescriptor artifact)
    {
        return artifact.Kind is ArtifactKind.DroppedFile or ArtifactKind.Screenshot or ArtifactKind.MemoryDump or ArtifactKind.PacketCapture ||
            ArtifactImportExpectations.Any(expectation =>
                string.Equals(artifact.CollectionName, expectation.CollectionName, StringComparison.OrdinalIgnoreCase));
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
            ["behaviorCounted"] = "false",
            ["sourceEventType"] = sourceEventType,
            ["downloadSelector"] = artifact.RelativePath,
            ["downloadSafeLink"] = artifact.SafeLink,
            ["nonbehavior"] = "true",
            ["behaviorScope"] = "artifact-import-metadata",
            ["notSampleBehavior"] = "true",
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
            ["hostImport"] = "true",
            ["importMode"] = "host-artifact-index",
            ["indexRoot"] = jobRoot,
            ["zhMessage"] = $"Host 已索引可下载产物：{ChineseKindName(artifact.Kind)}。",
            ["zhHint"] = "这是产物导入元数据，用于下载和溯源，不作为样本行为判定。"
        };

        AddIfNotEmpty(data, "sha256", artifact.Sha256);
        AddIfNotEmpty(data, "sourceArtifactSha256", artifact.Sha256);
        AddIfNotEmpty(data, "hash.sha256", artifact.Hashes.TryGetValue("sha256", out var hash) ? hash : artifact.Sha256);
        AddIfNotEmpty(data, "guestPath", artifact.GuestPath);
        AddIfNotEmpty(data, "sourceEventSource", MetadataValue(artifact.Metadata, "sourceEventSource"));
        AddIfNotEmpty(data, "sourceEventsPath", MetadataValue(artifact.Metadata, "sourceEventsPath"));
        AddIfNotEmpty(data, "processId", MetadataValue(artifact.Metadata, "processId"));
        AddIfNotEmpty(data, "rootProcessId", MetadataValue(artifact.Metadata, "rootProcessId"));
        AddIfNotEmpty(data, "processName", MetadataValue(artifact.Metadata, "processName"));

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
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["behaviorScope"] = "collection-health",
            ["notSampleBehavior"] = "true",
            ["sourceEventType"] = sourceEventType,
            ["sourceEventPath"] = sourceEventPath,
            ["artifactMissing"] = "true",
            ["healthStatus"] = "collection-health",
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
}

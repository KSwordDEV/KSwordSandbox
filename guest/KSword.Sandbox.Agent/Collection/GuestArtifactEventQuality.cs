using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Applies stable optional-artifact event metadata that is shared by dropped
/// files, screenshots, memory dumps, and packet captures.
/// </summary>
internal static class GuestArtifactEventQuality
{
    private const string ArtifactSelectorVersion = "artifact-selectors-v1";
    private const string MemoryDumpDescendantOptInMetadataVersion = "memory-dump-descendant-opt-in-v1";

    /// <summary>
    /// Normalizes one event in-place when it belongs to a guest artifact lane.
    /// Inputs are already-built SandboxEvent records; processing fills missing
    /// machine fields without replacing producer-specific diagnostics.
    /// </summary>
    public static void Apply(SandboxEvent evt)
    {
        if (!TryResolveLane(evt, out var lane))
        {
            return;
        }

        AddLaneDefaults(evt, lane);
        AddArtifactFieldDefaults(evt, lane);
        AddArtifactSelectorDefaults(evt.Data);
        AddRootLineageDefaults(evt);

        if (lane.SemanticType == "memory-dump")
        {
            AddMemoryDumpDescendantOptInDefaults(evt);
        }
    }

    private static void AddLaneDefaults(SandboxEvent evt, ArtifactLane lane)
    {
        AddIfMissing(evt.Data, "collectionName", lane.CollectionName);
        AddIfMissing(evt.Data, "evidenceRole", lane.EvidenceRole);
        AddIfMissing(evt.Data, "expectedRelativePath", lane.ExpectedRelativePath);
        AddIfMissing(evt.Data, "capturePolicy", lane.CapturePolicy);
        AddIfMissing(evt.Data, "artifactSemanticType", lane.SemanticType);
        AddIfMissing(evt.Data, "semanticEventCategory", "artifact-evidence");
        AddIfMissing(evt.Data, "artifactSelectorVersion", ArtifactSelectorVersion);

        var state = ArtifactState(evt);
        AddIfMissing(evt.Data, "status", state);
        AddIfMissing(evt.Data, "captureState", state);

        if (IsCollectionNoiseEvent(evt.EventType))
        {
            AddIfMissing(evt.Data, "behaviorCounted", "false");
            AddIfMissing(evt.Data, "nonbehavior", "true");
            AddIfMissing(evt.Data, "notSampleBehavior", "true");
        }
    }

    private static void AddArtifactFieldDefaults(SandboxEvent evt, ArtifactLane lane)
    {
        var data = evt.Data;
        var state = ArtifactState(evt);
        var relativePath = FirstNonEmpty(
            Value(data, "artifactRelativePath"),
            Value(data, "relativePath"),
            Value(data, "importPath"),
            Value(data, $"{lane.ShortName}RelativePath"));

        AddIfMissing(data, "artifactRelativePath", relativePath);
        AddIfMissing(data, "sizeBytes", string.Empty);
        AddIfMissing(data, "sha256", string.Empty);

        var artifactStatus = ArtifactPathStatus(data, state, relativePath);
        AddIfMissing(data, "artifactRelativePathStatus", artifactStatus);
        AddIfMissing(data, "sizeBytesStatus", ScalarStatus(data, "sizeBytes", artifactStatus));
        AddIfMissing(data, "sha256Status", ScalarStatus(data, "sha256", artifactStatus));
        AddIfMissing(data, "artifactHashStatus", HashStatus(data, artifactStatus));
        AddIfMissing(data, "hashStatus", HashStatus(data, artifactStatus));
        AddIfMissing(data, "artifactExists", ArtifactExists(data, state, relativePath));
        AddIfMissing(data, "artifactIntegrityState", ArtifactIntegrityState(data, state, artifactStatus));
    }

    private static void AddArtifactSelectorDefaults(Dictionary<string, string> data)
    {
        var relativePath = Value(data, "artifactRelativePath");
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return;
        }

        AddIfMissing(data, "artifactSelector", relativePath);
        AddIfMissing(data, "stableArtifactSelector", relativePath);
        AddIfMissing(data, "canonicalArtifactSelector", relativePath);
        AddIfMissing(data, "downloadSelector", relativePath);
        AddIfMissing(data, "artifactSafeLink", BuildSafeLink(relativePath));
        AddIfMissing(data, "artifactSelectorKind", "safe-output-relative-path");
        AddIfMissing(data, "artifactSelectorVersion", ArtifactSelectorVersion);
    }

    private static void AddRootLineageDefaults(SandboxEvent evt)
    {
        var rootProcessId = FirstNonEmpty(Value(evt.Data, "rootProcessId"), RootProcessIdFromEvent(evt));
        if (string.IsNullOrWhiteSpace(rootProcessId))
        {
            AddIfMissing(evt.Data, "rootProcessIdStatus", "unavailable");
            AddIfMissing(evt.Data, "treeLineageStatus", string.IsNullOrWhiteSpace(Value(evt.Data, "treeLineage")) ? "unavailable" : "stable");
            AddIfMissing(evt.Data, "lineageIncludesRoot", "false");
            return;
        }

        AddIfMissing(evt.Data, "rootProcessId", rootProcessId);
        AddIfMissing(evt.Data, "rootProcessIdStatus", "available");
        AddIfMissing(evt.Data, "treeLineage", rootProcessId);
        AddIfMissing(evt.Data, "treeDepth", "0");
        AddIfMissing(evt.Data, "treeLineageStatus", string.IsNullOrWhiteSpace(Value(evt.Data, "treeLineage")) ? "unavailable" : "stable");
        AddIfMissing(evt.Data, "lineageIncludesRoot", LineageContainsPid(Value(evt.Data, "treeLineage"), rootProcessId).ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
    }

    private static void AddMemoryDumpDescendantOptInDefaults(SandboxEvent evt)
    {
        var data = evt.Data;
        var enabled = string.Equals(Value(data, "captureEnabled"), "true", StringComparison.OrdinalIgnoreCase);
        var state = ArtifactState(evt);
        var disabled = string.Equals(state, "disabled", StringComparison.OrdinalIgnoreCase) || !enabled;

        AddIfMissing(data, "sensitiveArtifact", "true");
        AddIfMissing(data, "sensitiveArtifactReason", "process-memory-dump");
        AddIfMissing(data, "explicitOptInRequired", "true");
        AddIfMissing(data, "explicitOptInOption", "--memory-dump/--memory-dumps");
        AddIfMissing(data, "descendantDumpOptInRequired", "true");
        AddIfMissing(data, "descendantDumpOptInOption", "--memory-dump/--memory-dumps");
        AddIfMissing(data, "descendantDumpOptInMetadataVersion", MemoryDumpDescendantOptInMetadataVersion);
        AddIfMissing(data, "descendantDumpOptInMode", disabled ? "disabled-until-explicit-opt-in" : "inherits-memory-dump-opt-in");
        AddIfMissing(data, "descendantDumpOptInScope", disabled ? "disabled-until-memory-dump-requested" : "root-plus-direct-children-and-deeper-descendants");
        AddIfMissing(data, "dumpTargetSelectionMode", disabled ? "disabled-until-memory-dump-requested" : "root-plus-visible-descendants");
        AddIfMissing(data, "descendantProcessDumpEnabled", (!disabled).ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
        AddIfMissing(data, "directChildProcessDumpEnabled", (!disabled).ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
        AddIfMissing(data, "deeperDescendantProcessDumpEnabled", (!disabled).ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
        AddIfMissing(data, "memoryDumpOptInApplied", (!disabled).ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
        AddIfMissing(data, "rootDumpOptInApplied", RootDumpOptInApplied(data, disabled));
        AddIfMissing(data, "descendantDumpOptInApplied", DescendantDumpOptInApplied(data, disabled));
        AddIfMissing(data, "directChildDumpOptInApplied", DirectChildDumpOptInApplied(data, disabled));
        AddIfMissing(data, "deeperDescendantDumpOptInApplied", DeeperDescendantDumpOptInApplied(data, disabled));
    }

    private static bool TryResolveLane(SandboxEvent evt, out ArtifactLane lane)
    {
        var eventType = evt.EventType ?? string.Empty;
        if (eventType.StartsWith("artifact.dropped_file.", StringComparison.OrdinalIgnoreCase))
        {
            lane = ArtifactLane.DroppedFile;
            return true;
        }

        if (eventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase))
        {
            lane = ArtifactLane.Screenshot;
            return true;
        }

        if (eventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase))
        {
            lane = ArtifactLane.MemoryDump;
            return true;
        }

        if (eventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase))
        {
            lane = ArtifactLane.PacketCapture;
            return true;
        }

        if (IsDroppedFileCandidate(evt))
        {
            lane = ArtifactLane.DroppedFileCandidate;
            return true;
        }

        var collectionName = Value(evt.Data, "collectionName");
        lane = collectionName switch
        {
            "dropped-files" => ArtifactLane.DroppedFile,
            "screenshots" => ArtifactLane.Screenshot,
            "memory-dumps" => ArtifactLane.MemoryDump,
            "packet-captures" => ArtifactLane.PacketCapture,
            _ => ArtifactLane.None
        };
        return lane != ArtifactLane.None;
    }

    private static bool IsDroppedFileCandidate(SandboxEvent evt)
    {
        var eventType = evt.EventType ?? string.Empty;
        return (string.Equals(eventType, "file.created", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(eventType, "file.modified", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(eventType, "file.deleted", StringComparison.OrdinalIgnoreCase)) &&
            (Value(evt.Data, "evidenceRole").StartsWith("dropped-file", StringComparison.OrdinalIgnoreCase) ||
             !string.IsNullOrWhiteSpace(Value(evt.Data, "droppedFileArtifactCopyPolicy")));
    }

    private static string ArtifactState(SandboxEvent evt)
    {
        var existing = FirstNonEmpty(Value(evt.Data, "status"), Value(evt.Data, "captureState"));
        if (!string.IsNullOrWhiteSpace(existing))
        {
            return existing;
        }

        var eventType = evt.EventType ?? string.Empty;
        if (eventType.EndsWith(".captured", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".copied", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".written", StringComparison.OrdinalIgnoreCase))
        {
            return "captured";
        }

        if (eventType.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase))
        {
            return "disabled";
        }

        if (eventType.EndsWith(".skipped", StringComparison.OrdinalIgnoreCase))
        {
            return "skipped";
        }

        if (eventType.EndsWith(".failed", StringComparison.OrdinalIgnoreCase))
        {
            return "failed";
        }

        if (eventType.EndsWith(".summary", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".sweep", StringComparison.OrdinalIgnoreCase))
        {
            return "summary";
        }

        return "observed";
    }

    private static string ArtifactPathStatus(Dictionary<string, string> data, string state, string relativePath)
    {
        if (!string.IsNullOrWhiteSpace(Value(data, "artifactRelativePathStatus")))
        {
            return Value(data, "artifactRelativePathStatus");
        }

        if (!string.IsNullOrWhiteSpace(relativePath))
        {
            return string.Equals(state, "captured", StringComparison.OrdinalIgnoreCase)
                ? "captured"
                : state;
        }

        return state switch
        {
            "disabled" => "disabled",
            "skipped" => "not-created",
            "failed" => "not-created",
            "summary" => "not-applicable-summary",
            "deleted" => "not-created",
            "observed" => "not-created-by-file-diff",
            _ => "not-created"
        };
    }

    private static string ScalarStatus(Dictionary<string, string> data, string key, string artifactStatus)
    {
        if (!string.IsNullOrWhiteSpace(Value(data, key)))
        {
            return "computed";
        }

        return artifactStatus switch
        {
            "captured" => "missing",
            "verified" => "computed",
            "disabled" => "disabled",
            "not-applicable-summary" => "not-applicable-summary",
            "not-created-by-file-diff" => "not-created-by-file-diff",
            "conversion-pending" => "conversion-pending",
            "expected-pending-conversion" => "expected-pending-conversion",
            "conversion-pending-pcapng" => "conversion-pending-pcapng",
            _ => "not-created"
        };
    }

    private static string HashStatus(Dictionary<string, string> data, string artifactStatus)
    {
        var sha256 = Value(data, "sha256");
        if (!string.IsNullOrWhiteSpace(sha256))
        {
            return "computed";
        }

        return artifactStatus switch
        {
            "captured" => "missing",
            "disabled" => "disabled",
            "not-applicable-summary" => "not-applicable-summary",
            "not-created-by-file-diff" => "not-created-by-file-diff",
            "conversion-pending" => "conversion-pending",
            "expected-pending-conversion" => "expected-pending-conversion",
            _ => "not-created"
        };
    }

    private static string ArtifactExists(Dictionary<string, string> data, string state, string relativePath)
    {
        if (!string.IsNullOrWhiteSpace(Value(data, "artifactExists")))
        {
            return Value(data, "artifactExists");
        }

        return (!string.IsNullOrWhiteSpace(relativePath) &&
                string.Equals(state, "captured", StringComparison.OrdinalIgnoreCase))
            .ToString(CultureInfo.InvariantCulture)
            .ToLowerInvariant();
    }

    private static string ArtifactIntegrityState(Dictionary<string, string> data, string state, string artifactStatus)
    {
        if (!string.IsNullOrWhiteSpace(Value(data, "sha256")))
        {
            return "verified";
        }

        return state switch
        {
            "disabled" => "disabled",
            "skipped" => "skipped",
            "failed" => "failed",
            "summary" => "not-applicable-summary",
            "captured" when string.Equals(artifactStatus, "captured", StringComparison.OrdinalIgnoreCase) => "pending-hash",
            _ => artifactStatus
        };
    }

    private static string RootProcessIdFromEvent(SandboxEvent evt)
    {
        if (evt.ProcessId is null || IsMemoryDumpDescendantEvent(evt))
        {
            return string.Empty;
        }

        return evt.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
    }

    private static bool IsMemoryDumpDescendantEvent(SandboxEvent evt)
    {
        if (!evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return Value(evt.Data, "targetProcessId").Length > 0 ||
            string.Equals(Value(evt.Data, "descendantProcessDumpTarget"), "true", StringComparison.OrdinalIgnoreCase);
    }

    private static string RootDumpOptInApplied(Dictionary<string, string> data, bool disabled)
    {
        if (disabled)
        {
            return "false";
        }

        var role = FirstNonEmpty(Value(data, "targetProcessRole"), Value(data, "processRole"));
        return (string.Equals(role, "root", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(role, "sample-root-context", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Value(data, "rootProcessDumpTarget"), "true", StringComparison.OrdinalIgnoreCase) ||
                HasPositiveCount(data, "rootTargetCount"))
            .ToString(CultureInfo.InvariantCulture)
            .ToLowerInvariant();
    }

    private static string DescendantDumpOptInApplied(Dictionary<string, string> data, bool disabled)
    {
        if (disabled)
        {
            return "false";
        }

        return (string.Equals(Value(data, "descendantProcessDumpTarget"), "true", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Value(data, "childProcessDumpTarget"), "true", StringComparison.OrdinalIgnoreCase) ||
                HasPositiveCount(data, "descendantTargetCount") ||
                HasPositiveCount(data, "childTargetCount"))
            .ToString(CultureInfo.InvariantCulture)
            .ToLowerInvariant();
    }

    private static string DirectChildDumpOptInApplied(Dictionary<string, string> data, bool disabled)
    {
        if (disabled)
        {
            return "false";
        }

        return (string.Equals(Value(data, "directChildProcessDumpTarget"), "true", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Value(data, "targetProcessRole"), "direct-child", StringComparison.OrdinalIgnoreCase) ||
                HasPositiveCount(data, "directChildTargetCount"))
            .ToString(CultureInfo.InvariantCulture)
            .ToLowerInvariant();
    }

    private static string DeeperDescendantDumpOptInApplied(Dictionary<string, string> data, bool disabled)
    {
        if (disabled)
        {
            return "false";
        }

        return (string.Equals(Value(data, "deeperDescendantProcessDumpTarget"), "true", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Value(data, "targetProcessRole"), "descendant", StringComparison.OrdinalIgnoreCase) ||
                HasPositiveCount(data, "deeperDescendantTargetCount"))
            .ToString(CultureInfo.InvariantCulture)
            .ToLowerInvariant();
    }

    private static bool HasPositiveCount(Dictionary<string, string> data, string key)
    {
        return long.TryParse(Value(data, key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value > 0;
    }

    private static bool IsCollectionNoiseEvent(string? eventType)
    {
        if (string.IsNullOrWhiteSpace(eventType))
        {
            return false;
        }

        return eventType.StartsWith("artifact.dropped_file.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LineageContainsPid(string lineage, string rootProcessId)
    {
        if (string.IsNullOrWhiteSpace(lineage) || string.IsNullOrWhiteSpace(rootProcessId))
        {
            return false;
        }

        return lineage
            .Split('>', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(token => string.Equals(token, rootProcessId, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildSafeLink(string relativePath)
    {
        return string.Join(
            "/",
            relativePath
                .Replace('\\', '/')
                .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(Uri.EscapeDataString));
    }

    private static string Value(Dictionary<string, string> data, string key)
    {
        return data.TryGetValue(key, out var value) ? value : string.Empty;
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

    private static void AddIfMissing(Dictionary<string, string> data, string key, string value)
    {
        if (!data.ContainsKey(key) || string.IsNullOrWhiteSpace(data[key]))
        {
            data[key] = value;
        }
    }

    private sealed record ArtifactLane(
        string CollectionName,
        string EvidenceRole,
        string ExpectedRelativePath,
        string CapturePolicy,
        string SemanticType,
        string ShortName)
    {
        public static ArtifactLane None { get; } = new(string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);

        public static ArtifactLane DroppedFile { get; } = new(
            "dropped-files",
            "dropped-file",
            "artifacts/dropped-files/**",
            "explicit-opt-in-copy-working-directory-new-files",
            "dropped-file",
            "droppedFile");

        public static ArtifactLane DroppedFileCandidate { get; } = new(
            "file-diff",
            "dropped-file-candidate",
            "artifacts/dropped-files/**",
            "always-on-working-directory-file-diff",
            "dropped-file-candidate",
            "droppedFile");

        public static ArtifactLane Screenshot { get; } = new(
            "screenshots",
            "screenshot",
            "screenshots/*.bmp",
            "explicit-opt-in-screenshot",
            "screenshot",
            "screenshot");

        public static ArtifactLane MemoryDump { get; } = new(
            "memory-dumps",
            "memory-dump",
            "memory-dumps/*.dmp",
            "explicit-opt-in-sensitive-memory-dump",
            "memory-dump",
            "memoryDump");

        public static ArtifactLane PacketCapture { get; } = new(
            "packet-captures",
            "packet-capture",
            "packet-captures/*.pcapng",
            "explicit-opt-in-network-packet-capture",
            "packet-capture",
            "packetCapture");
    }
}

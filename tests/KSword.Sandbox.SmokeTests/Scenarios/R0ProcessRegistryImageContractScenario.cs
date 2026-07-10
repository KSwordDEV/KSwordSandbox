using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the static R0 process/image/registry producer contract without
/// loading a kernel driver. Inputs are repository source and docs; processing
/// checks callback registration, payload field coverage, safety gates, and
/// unregister paths; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class R0ProcessRegistryImageContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.process-registry-image.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var processSource = ReadRepositoryText(
            context,
            "driver", "KSword.Sandbox.Driver", "src", "Producers", "Process", "ProcessMonitor.c");
        var processHeader = ReadRepositoryText(
            context,
            "driver", "KSword.Sandbox.Driver", "src", "Producers", "Process", "ProcessMonitor.h");
        var registrySource = ReadRepositoryText(
            context,
            "driver", "KSword.Sandbox.Driver", "src", "Producers", "Registry", "RegistryMonitor.c");
        var registryHeader = ReadRepositoryText(
            context,
            "driver", "KSword.Sandbox.Driver", "src", "Producers", "Registry", "RegistryMonitor.h");
        var abiHeader = ReadRepositoryText(
            context,
            "driver", "KSword.Sandbox.Driver", "include", "KSwordSandboxDriverIoctl.h");
        var collectorSource = ReadRepositoryTreeText(
            context,
            "guest", "KSword.Sandbox.R0Collector", "src");
        var producerDoc = ReadRepositoryText(context, "docs", "r0-process-registry-image.md");

        AssertProcessProducer(processSource, processHeader, abiHeader, collectorSource, producerDoc);
        AssertImageProducer(processSource, abiHeader, collectorSource, producerDoc);
        AssertRegistryProducer(registrySource, registryHeader, abiHeader, collectorSource, producerDoc);
        AssertSafetyAndUnload(processSource, registrySource, producerDoc);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 process/image/registry producer contract is present."
        });
    }

    /// <summary>
    /// Checks process callback registration and payload fields. Inputs are source
    /// and docs; processing performs substring assertions; return value is none.
    /// </summary>
    private static void AssertProcessProducer(
        string processSource,
        string processHeader,
        string abiHeader,
        string collectorSource,
        string producerDoc)
    {
        RequireContains(processHeader, "KswInitializeProcessMonitor", "Process monitor should expose initialization.");
        RequireContains(processHeader, "KswUninitializeProcessMonitor", "Process monitor should expose teardown.");
        RequireContains(processSource, "PsSetCreateProcessNotifyRoutineEx", "Process producer should prefer the Ex callback.");
        RequireContains(processSource, "PsSetCreateProcessNotifyRoutine(", "Process producer should keep a legacy fallback.");
        RequireContains(processSource, "KswProcessCreateNotifyLegacy", "Process producer should implement the legacy callback path.");
        RequireContains(processSource, "KswSandboxEventTypeProcess", "Process events should use the public process event type.");
        RequireContains(processSource, "KswSandboxProcessOperationCreate", "Process create operation should be emitted.");
        RequireContains(processSource, "KswSandboxProcessOperationExit", "Process exit operation should be emitted.");
        RequireContains(processSource, "ParentProcessId", "Process payload should include parent process lineage.");
        RequireContains(processSource, "CreatingProcessId", "Process payload should include creator process lineage.");
        RequireContains(processSource, "KswRememberProcessLineage", "Create callbacks should cache lineage for exit events.");
        RequireContains(processSource, "KswTakeProcessLineage", "Exit callbacks should replay cached lineage.");
        RequireContains(processSource, "KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT", "Process status presence should be flagged.");
        RequireContains(processSource, "KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT", "Process image path presence should be flagged.");
        RequireContains(processSource, "KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT", "Process command-line presence should be flagged.");
        RequireContains(abiHeader, "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD", "Public ABI should define the process payload.");
        RequireContains(collectorSource, "payloadSchema", "Collector should emit typed payload schema metadata.");
        RequireContains(collectorSource, "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD", "Collector should parse process payloads.");
        RequireContains(producerDoc, "driver.process", "Producer doc should name the process JSONL event.");
    }

    /// <summary>
    /// Checks image-load callback registration and payload fields. Inputs are
    /// source and docs; processing performs substring assertions; return value is none.
    /// </summary>
    private static void AssertImageProducer(
        string processSource,
        string abiHeader,
        string collectorSource,
        string producerDoc)
    {
        RequireContains(processSource, "PsSetLoadImageNotifyRoutine", "Image producer should register image-load callbacks.");
        RequireContains(processSource, "PsRemoveLoadImageNotifyRoutine", "Image producer should unregister image-load callbacks.");
        RequireContains(processSource, "KswLoadImageNotify", "Image producer callback should be implemented.");
        RequireContains(processSource, "KswSandboxEventTypeImage", "Image events should use the public image event type.");
        RequireContains(processSource, "ImageBase", "Image payload should include base address.");
        RequireContains(processSource, "ImageSize", "Image payload should include image size.");
        RequireContains(processSource, "KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE", "Image payload should flag system-mode images.");
        RequireContains(processSource, "KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT", "Image path presence should be flagged.");
        RequireContains(abiHeader, "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD", "Public ABI should define the image payload.");
        RequireContains(collectorSource, "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD", "Collector should parse image payloads.");
        RequireContains(producerDoc, "image.load", "Producer doc should name the image JSONL event.");
    }

    /// <summary>
    /// Checks registry callback registration, operation coverage, and payload
    /// fields. Inputs are source and docs; processing performs substring assertions.
    /// </summary>
    private static void AssertRegistryProducer(
        string registrySource,
        string registryHeader,
        string abiHeader,
        string collectorSource,
        string producerDoc)
    {
        RequireContains(registryHeader, "CmRegisterCallbackEx", "Registry header should document callback registration.");
        RequireContains(registrySource, "CmRegisterCallbackEx", "Registry producer should register Configuration Manager callbacks.");
        RequireContains(registrySource, "CmUnRegisterCallback", "Registry producer should unregister Configuration Manager callbacks.");
        RequireContains(registrySource, "KswSandboxEventTypeRegistry", "Registry events should use the public registry event type.");
        RequireContains(registrySource, "CmCallbackGetKeyObjectIDEx", "Registry producer should resolve key object paths when available.");
        RequireContains(registrySource, "CmCallbackReleaseKeyObjectIDEx", "Registry producer should release resolved key names.");

        foreach (var notifyClass in new[]
        {
            "RegNtPostCreateKeyEx",
            "RegNtPostOpenKeyEx",
            "RegNtPostSetValueKey",
            "RegNtPostDeleteValueKey",
            "RegNtPostDeleteKey",
            "RegNtPostRenameKey"
        })
        {
            RequireContains(registrySource, notifyClass, $"Registry producer should handle {notifyClass}.");
        }

        foreach (var operation in new[]
        {
            "KswSandboxRegistryOperationCreateKey",
            "KswSandboxRegistryOperationOpenKey",
            "KswSandboxRegistryOperationSetValue",
            "KswSandboxRegistryOperationDeleteValue",
            "KswSandboxRegistryOperationDeleteKey",
            "KswSandboxRegistryOperationRenameKey"
        })
        {
            RequireContains(registrySource, operation, $"Registry producer should emit {operation}.");
        }

        RequireContains(registrySource, "KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT", "Registry key presence should be flagged.");
        RequireContains(registrySource, "KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT", "Registry value presence should be flagged.");
        RequireContains(registrySource, "KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_STATUS_PRESENT", "Registry status presence should be flagged.");
        RequireContains(abiHeader, "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD", "Public ABI should define the registry payload.");
        RequireContains(collectorSource, "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD", "Collector should parse registry payloads.");
        RequireContains(producerDoc, "driver.registry", "Producer doc should name the registry JSONL event.");
    }

    /// <summary>
    /// Checks IRQL/string safety and unload state. Inputs are producer source and
    /// docs; processing performs substring assertions; return value is none.
    /// </summary>
    private static void AssertSafetyAndUnload(string processSource, string registrySource, string producerDoc)
    {
        RequireContains(processSource, "KswPrepareProcessCallbackString", "Process producer should gate callback strings.");
        RequireContains(registrySource, "KswPrepareRegistryCallbackString", "Registry producer should gate callback strings.");
        RequireContains(processSource, "KeGetCurrentIrql() > APC_LEVEL", "Process string copy should avoid elevated IRQL.");
        RequireContains(registrySource, "KeGetCurrentIrql() > APC_LEVEL", "Registry string copy should avoid elevated IRQL.");
        RequireContains(processSource, "Source->MaximumLength", "Process string copy should clamp to MaximumLength.");
        RequireContains(registrySource, "Source->MaximumLength", "Registry string copy should clamp to MaximumLength.");
        RequireContains(processSource, "KswCopyUnicodePrefix", "Process producer should use bounded UTF-16 copies.");
        RequireContains(registrySource, "KswCopyUnicodePrefix", "Registry producer should use bounded UTF-16 copies.");
        RequireContains(processSource, "InterlockedExchange(&g_KswProcessMonitorActive, 0)", "Process teardown should disable emission first.");
        RequireContains(registrySource, "InterlockedExchange(&g_KswRegistryMonitorActive, 0)", "Registry teardown should disable emission first.");
        RequireContains(processSource, "InterlockedExchange(&g_KswImageCallbackRegistered, 0)", "Image teardown should clear registration state atomically.");
        RequireContains(registrySource, "InterlockedExchange(&g_KswRegistryCallbackRegistered, 0)", "Registry teardown should clear registration state atomically.");
        RequireContains(producerDoc, "IRQL and string safety", "Producer doc should document string safety.");
        RequireContains(producerDoc, "Unload and failure behavior", "Producer doc should document unload behavior.");
    }

    /// <summary>
    /// Reads a repository file as text. Inputs are the smoke context and relative
    /// path segments; processing joins them under RepositoryRoot; return value is file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        var path = Path.Combine(allSegments);
        SmokeAssert.True(File.Exists(path), $"Required R0 process/registry/image contract file is missing: {path}");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Reads text source files from a repository directory. Inputs are context
    /// and relative path segments; processing concatenates top-level C/C++ files
    /// so the check survives collector source split/merge refactors.
    /// </summary>
    private static string ReadRepositoryTreeText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        var directory = Path.Combine(allSegments);
        SmokeAssert.True(Directory.Exists(directory), $"Required R0 source directory is missing: {directory}");

        var sourceFiles = Directory.EnumerateFiles(directory)
            .Where(path =>
                path.EndsWith(".cpp", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".h", StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        SmokeAssert.True(sourceFiles.Length > 0, $"Required R0 source directory has no source files: {directory}");
        return string.Join(Environment.NewLine, sourceFiles.Select(File.ReadAllText));
    }

    /// <summary>
    /// Requires a text fragment to be present. Inputs are content, expected text,
    /// and failure message; processing throws on absence; return value is none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Exercises the smallest VM-free operator path end-to-end. Inputs are
/// temporary sample/upload/guest-output files; processing simulates selection,
/// upload, planning, guest telemetry/artifacts, import, rule classification,
/// bilingual reports, and live UI JSON contracts; the scenario returns a
/// deterministic smoke result without starting Hyper-V or loading a driver.
/// </summary>
internal sealed class SyntheticEndToEndSmokeScenario : ISmokeTestScenario
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly JsonSerializerOptions JsonLineOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    public string ScenarioId => "synthetic.e2e-smoke.contract";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var runtimeRoot = Path.Combine(context.RuntimeRoot, "synthetic-e2e", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);

        var upload = await SimulateSelectionAndUploadAsync(runtimeRoot, cancellationToken);
        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json"));
        var service = new SandboxJobService(BuildSyntheticConfig(context, runtimeRoot), rules);

        var planned = service.Plan(new SandboxSubmission
        {
            SamplePath = upload.StoredPath,
            DisplayName = upload.OriginalFileName,
            DurationSeconds = 7,
            DryRun = true,
            UseMockCollector = true,
            CollectDroppedFiles = true,
            CaptureScreenshots = true,
            CaptureMemoryDumps = true,
            CapturePacketCapture = false
        });
        AssertPlan(planned, upload);

        var executionSaved = service.SaveRunbookExecutionResult(planned.JobId, BuildSyntheticRunbookExecution(planned));
        AssertRunbookProgress(service, executionSaved);

        var guestEventsPath = await WriteSyntheticGuestOutputAsync(executionSaved, cancellationToken);
        AssertLiveSnapshotBeforeImport(service, executionSaved.JobId, guestEventsPath);

        var imported = service.ImportGuestEvents(executionSaved.JobId, guestEventsPath);
        var report = AssertImportedReport(imported, upload, guestEventsPath);
        AssertBilingualReports(imported, report);
        AssertArtifactIndex(service, imported);
        AssertLiveUiContract(context, service, imported.JobId, guestEventsPath);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Synthetic select/upload -> plan -> guest telemetry/artifacts -> import -> rules -> bilingual reports -> live UI contract passed.",
            Artifacts =
            [
                imported.JsonReportPath ?? string.Empty,
                imported.HtmlReportZhPath ?? string.Empty,
                imported.HtmlReportEnPath ?? string.Empty
            ]
        };
    }

    private static SandboxConfig BuildSyntheticConfig(SmokeTestContext context, string runtimeRoot)
    {
        return new SandboxConfig
        {
            HyperV = new HyperVConfig
            {
                GoldenVmName = "KSwordSyntheticSmoke-Golden",
                GoldenSnapshotName = "Clean"
            },
            Guest = new GuestConfig
            {
                UserName = "SyntheticSmokeUser",
                WorkingDirectory = @"C:\KSwordSandbox"
            },
            Analysis = new AnalysisConfig
            {
                DefaultDurationSeconds = 7,
                MaxDurationSeconds = 60,
                MaxSampleBytes = 1024 * 1024
            },
            ArtifactCollection = new ArtifactCollectionConfig
            {
                CollectDroppedFiles = true,
                CaptureScreenshots = true,
                CaptureMemoryDumps = true,
                CapturePacketCapture = false
            },
            Paths = new SandboxPaths
            {
                RuntimeRoot = runtimeRoot,
                RulesDirectory = context.RulesDirectory,
                GuestPayloadRoot = Path.Combine(runtimeRoot, "payload", "guest-tools")
            },
            Driver = new DriverConfig
            {
                Enabled = true,
                UseMockCollector = true,
                DevicePath = @"\\.\KSwordSandboxDriver",
                R0CollectorPathInGuest = @"C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe",
                EventJsonLinesPath = @"C:\KSwordSandbox\out\driver-events.jsonl"
            }
        };
    }

    private static async Task<SyntheticUploadContract> SimulateSelectionAndUploadAsync(string runtimeRoot, CancellationToken cancellationToken)
    {
        var selectionRoot = Path.Combine(runtimeRoot, "operator-selection");
        var nestedRoot = Path.Combine(selectionRoot, "nested");
        Directory.CreateDirectory(nestedRoot);

        var sourceSamplePath = Path.Combine(nestedRoot, "synthetic-operator.exe");
        await File.WriteAllTextAsync(
            sourceSamplePath,
            "synthetic executable placeholder used only by the VM-free smoke path",
            cancellationToken);

        var scanResult = new ExecutableTargetScanner().Scan(new ExecutableScanRequest
        {
            Path = selectionRoot,
            MaxDepth = 2,
            MaxResults = 10
        });
        var selected = scanResult.Candidates.SingleOrDefault(candidate =>
            string.Equals(candidate.FullPath, sourceSamplePath, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(selected is not null, "Executable selection scan should find the synthetic .exe candidate.");

        var uploadRoot = Path.Combine(runtimeRoot, "uploads");
        Directory.CreateDirectory(uploadRoot);
        var storedPath = Path.Combine(uploadRoot, "uploaded-synthetic-operator.exe");
        File.Copy(selected!.FullPath, storedPath, overwrite: true);

        var upload = new SyntheticUploadContract(
            OriginalFileName: selected.FileName,
            StoredPath: storedPath,
            Length: new FileInfo(storedPath).Length,
            Sha256: ComputeSha256(storedPath));

        var uploadJson = JsonSerializer.Serialize(upload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var document = JsonDocument.Parse(uploadJson);
        var root = document.RootElement;
        SmokeAssert.True(root.TryGetProperty("originalFileName", out var originalFileName) && originalFileName.GetString() == selected.FileName, "Upload contract JSON should expose camelCase originalFileName.");
        SmokeAssert.True(root.TryGetProperty("storedPath", out var storedPathJson) && storedPathJson.GetString() == storedPath, "Upload contract JSON should expose camelCase storedPath.");
        SmokeAssert.True(root.TryGetProperty("length", out var lengthJson) && lengthJson.GetInt64() == upload.Length, "Upload contract JSON should expose length.");
        SmokeAssert.True(root.TryGetProperty("sha256", out var sha256Json) && sha256Json.GetString() == upload.Sha256, "Upload contract JSON should expose sha256.");

        return upload;
    }

    private static void AssertPlan(AnalysisJob planned, SyntheticUploadContract upload)
    {
        SmokeAssert.True(planned.Status == AnalysisStatus.Planned, "Synthetic upload should produce a planned job.");
        SmokeAssert.True(planned.Sample is not null, "Planned job should include sample identity.");
        SmokeAssert.True(string.Equals(planned.Sample!.FullPath, upload.StoredPath, StringComparison.OrdinalIgnoreCase), "Planned sample path should point at the simulated uploaded file.");
        SmokeAssert.True(planned.Sample.SizeBytes == upload.Length, "Planned sample size should match the uploaded length.");
        SmokeAssert.True(string.Equals(planned.Sample.Sha256, upload.Sha256, StringComparison.OrdinalIgnoreCase), "Planned sample SHA-256 should match the upload contract.");
        SmokeAssert.True(planned.Runbook is not null, "Planned job should include a Hyper-V runbook.");
        SmokeAssert.True(planned.Runbook!.Steps.Count > 0, "Planned runbook should contain reviewable steps.");
        SmokeAssert.True(planned.Runbook.Steps.Any(step => step.Id == "run-agent"), "Planned runbook should include the guest agent step.");
        var runAgent = planned.Runbook.Steps.Single(step => step.Id == "run-agent");
        RequireContains(runAgent.PowerShell, "--collect-dropped-files", "Runbook should pass dropped-file collection into the guest agent.");
        RequireContains(runAgent.PowerShell, "--screenshot", "Runbook should pass screenshot collection into the guest agent.");
        RequireContains(runAgent.PowerShell, "--memory-dump", "Runbook should pass memory-dump collection into the guest agent.");
        RequireContains(runAgent.PowerShell, "--driver-events", "Runbook should pass driver JSONL output into the guest agent.");
        RequireContains(runAgent.PowerShell, "--r0-mock", "Runbook should use mock R0 collection for the VM-free smoke path.");
        SmokeAssert.True(File.Exists(planned.JsonReportPath), "Planning should write report.json.");
        SmokeAssert.True(File.Exists(planned.HtmlReportPath), "Planning should write compatibility report.html.");
        SmokeAssert.True(File.Exists(planned.HtmlReportZhPath), "Planning should write report.zh.html.");
        SmokeAssert.True(File.Exists(planned.HtmlReportEnPath), "Planning should write report.en.html.");
    }

    private static SandboxRunbookExecutionResult BuildSyntheticRunbookExecution(AnalysisJob job)
    {
        var runbook = job.Runbook ?? throw new InvalidOperationException("Runbook is required.");
        var started = DateTimeOffset.UtcNow.AddSeconds(-runbook.Steps.Count);
        var stepResults = runbook.Steps
            .Select((step, index) => new SandboxRunbookStepExecutionResult
            {
                StepIndex = index,
                StepId = step.Id,
                Title = step.Title,
                PowerShell = step.PowerShell,
                Skipped = true,
                Success = true,
                ExitCode = 0,
                StartedAtUtc = started.AddMilliseconds(index * 25),
                Duration = TimeSpan.FromMilliseconds(5),
                RequiresElevation = step.RequiresElevation,
                MutatesVmState = step.MutatesVmState,
                Message = "Synthetic smoke recorded the planned step without starting Hyper-V."
            })
            .ToList();

        return new SandboxRunbookExecutionResult
        {
            JobId = job.JobId,
            TargetVmName = runbook.TargetVmName,
            Mode = SandboxRunbookExecutionMode.DryRun,
            Success = true,
            TotalSteps = runbook.Steps.Count,
            ExecutedSteps = 0,
            StartedAtUtc = started,
            Duration = TimeSpan.FromMilliseconds(stepResults.Count * 5),
            RequiresElevation = runbook.Steps.Any(step => step.RequiresElevation),
            StepResults = stepResults,
            Message = "Synthetic VM-free runbook execution recorded."
        };
    }

    private static void AssertRunbookProgress(SandboxJobService service, AnalysisJob job)
    {
        SmokeAssert.True(File.Exists(job.RunbookExecutionResultPath), "Synthetic runbook execution should be persisted.");
        SmokeAssert.True(service.TryGetRunbookProgress(job.JobId, out var snapshot), "Synthetic runbook progress should be available for the live UI.");
        SmokeAssert.True(snapshot.State == SandboxRunbookProgressStates.Completed, "Synthetic runbook progress should be completed.");
        SmokeAssert.True(snapshot.TotalSteps == job.Runbook!.Steps.Count, "Synthetic runbook progress should cover every runbook step.");
        SmokeAssert.True(snapshot.Steps.Count == job.Runbook.Steps.Count, "Synthetic runbook progress should expose one UI-safe row per runbook step.");

        var progressJson = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        SmokeAssert.True(!progressJson.Contains("\"powerShell\"", StringComparison.Ordinal), "Live UI progress JSON should not expose a PowerShell command field.");
        SmokeAssert.True(!progressJson.Contains("\"standardOutput\"", StringComparison.Ordinal), "Live UI progress JSON should not expose stdout fields.");
        SmokeAssert.True(!progressJson.Contains("\"standardError\"", StringComparison.Ordinal), "Live UI progress JSON should not expose stderr fields.");
    }

    private static async Task<string> WriteSyntheticGuestOutputAsync(AnalysisJob job, CancellationToken cancellationToken)
    {
        var jobRoot = Path.GetDirectoryName(job.JsonReportPath ?? string.Empty) ?? throw new InvalidOperationException("Job root should be resolvable from report.json.");
        var guestRoot = Path.Combine(jobRoot, "guest", job.JobId.ToString("N"));
        var droppedRoot = Path.Combine(guestRoot, "artifacts", "dropped-files");
        var screenshotRoot = Path.Combine(guestRoot, "screenshots");
        var memoryRoot = Path.Combine(guestRoot, "memory-dumps");
        Directory.CreateDirectory(droppedRoot);
        Directory.CreateDirectory(screenshotRoot);
        Directory.CreateDirectory(memoryRoot);

        var droppedRelativePath = "artifacts/dropped-files/ksword-e2e-drop.bin";
        var screenshotRelativePath = "screenshots/after-run.bmp";
        var memoryRelativePath = "memory-dumps/synthetic-pid4242.dmp";
        await File.WriteAllTextAsync(Path.Combine(guestRoot, droppedRelativePath), "synthetic dropped file evidence", cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(guestRoot, screenshotRelativePath), [0x42, 0x4d, 0x16, 0x00, 0x00, 0x00], cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(guestRoot, memoryRelativePath), Encoding.ASCII.GetBytes("MDMP synthetic smoke"), cancellationToken);

        var timestamp = DateTimeOffset.UtcNow.AddMinutes(-2);
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "process.start",
                Timestamp = timestamp,
                Source = "guest",
                ProcessName = "powershell.exe",
                ProcessId = 4242,
                ParentProcessId = 4100,
                Path = @"C:\KSwordSandbox\incoming\uploaded-synthetic-operator.exe",
                CommandLine = @"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\KSwordSandbox\incoming\uploaded-synthetic-operator.exe",
                Data =
                {
                    ["selectionSource"] = "synthetic-scanner",
                    ["uploadSource"] = "simulated-multipart-upload"
                }
            },
            new()
            {
                EventType = "file.created",
                Timestamp = timestamp.AddSeconds(1),
                Source = "guest",
                ProcessName = "uploaded-synthetic-operator.exe",
                ProcessId = 4242,
                Path = @"C:\Users\Public\ksword-e2e-drop.bin",
                Data =
                {
                    ["artifactRelativePath"] = droppedRelativePath,
                    ["collectionName"] = "dropped-files",
                    ["captureState"] = "captured"
                }
            },
            new()
            {
                EventType = "network.tcp",
                Timestamp = timestamp.AddSeconds(2),
                Source = "guest",
                ProcessName = "uploaded-synthetic-operator.exe",
                ProcessId = 4242,
                Data =
                {
                    ["remoteAddress"] = "203.0.113.44",
                    ["remotePort"] = "443",
                    ["state"] = "Established",
                    ["protocol"] = "tcp"
                }
            },
            new()
            {
                EventType = "registry.set",
                Timestamp = timestamp.AddSeconds(3),
                Source = "guest",
                ProcessName = "uploaded-synthetic-operator.exe",
                ProcessId = 4242,
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KSwordSyntheticSmoke",
                Data =
                {
                    ["value"] = @"C:\KSwordSandbox\incoming\uploaded-synthetic-operator.exe"
                }
            },
            new()
            {
                EventType = "screenshot.captured",
                Timestamp = timestamp.AddSeconds(4),
                Source = "guest",
                ProcessName = "uploaded-synthetic-operator.exe",
                ProcessId = 4242,
                Path = @"C:\KSwordSandbox\out\screenshots\after-run.bmp",
                Data =
                {
                    ["screenshotRelativePath"] = screenshotRelativePath,
                    ["collectionName"] = "screenshots",
                    ["capturePhase"] = "after-run",
                    ["captureState"] = "captured"
                }
            },
            new()
            {
                EventType = "memory_dump.captured",
                Timestamp = timestamp.AddSeconds(5),
                Source = "guest",
                ProcessName = "uploaded-synthetic-operator.exe",
                ProcessId = 4242,
                Path = @"C:\KSwordSandbox\out\memory-dumps\synthetic-pid4242.dmp",
                Data =
                {
                    ["memoryDumpRelativePath"] = memoryRelativePath,
                    ["collectionName"] = "memory-dumps",
                    ["capturePhase"] = "after-start",
                    ["captureState"] = "captured"
                }
            }
        };

        var eventsPath = Path.Combine(guestRoot, "events.json");
        await File.WriteAllTextAsync(eventsPath, JsonSerializer.Serialize(events, JsonOptions), cancellationToken);

        var driverEventsPath = Path.Combine(guestRoot, "driver-events.jsonl");
        await File.WriteAllLinesAsync(
            driverEventsPath,
            BuildSyntheticDriverEvents(timestamp.AddSeconds(10)).Select(evt => JsonSerializer.Serialize(evt, JsonLineOptions)),
            cancellationToken);
        await File.WriteAllTextAsync(
            Path.Combine(guestRoot, "partial-driver-events.jsonl"),
            "{\"eventType\":\"driver.partial\",\"source\":\"driver\"",
            cancellationToken);

        await WriteArtifactManifestAsync(
            job.JobId,
            guestRoot,
            droppedRelativePath,
            screenshotRelativePath,
            memoryRelativePath,
            cancellationToken);

        return eventsPath;
    }

    private static IReadOnlyList<SandboxEvent> BuildSyntheticDriverEvents(DateTimeOffset timestamp) =>
    [
        new SandboxEvent
        {
            EventType = "driver.file.create",
            Timestamp = timestamp,
            Source = "driver",
            ProcessName = "uploaded-synthetic-operator.exe",
            ProcessId = 4242,
            Path = @"C:\Users\Public\ksword-e2e-drop.bin",
            Data =
            {
                ["artifactRelativePath"] = "artifacts/dropped-files/ksword-e2e-drop.bin",
                ["driverEventPath"] = "driver-events.jsonl"
            }
        },
        new SandboxEvent
        {
            EventType = "registry.set",
            Timestamp = timestamp.AddSeconds(1),
            Source = "driver",
            ProcessName = "uploaded-synthetic-operator.exe",
            ProcessId = 4242,
            Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KSwordSyntheticSmoke",
            Data =
            {
                ["value"] = @"C:\KSwordSandbox\incoming\uploaded-synthetic-operator.exe",
                ["driverEventPath"] = "driver-events.jsonl"
            }
        },
        new SandboxEvent
        {
            EventType = "r0collector.mockDriverEvent",
            Timestamp = timestamp.AddSeconds(2),
            Source = "r0collector",
            ProcessName = "KSword.Sandbox.R0Collector.exe",
            ProcessId = 5000,
            Path = @"\\.\KSwordSandboxDriver",
            Data =
            {
                ["mock"] = "true",
                ["driverEventPath"] = "driver-events.jsonl",
                ["devicePath"] = @"\\.\KSwordSandboxDriver"
            }
        }
    ];

    private static async Task WriteArtifactManifestAsync(
        Guid jobId,
        string guestRoot,
        string droppedRelativePath,
        string screenshotRelativePath,
        string memoryRelativePath,
        CancellationToken cancellationToken)
    {
        var manifest = new ArtifactManifest
        {
            JobId = jobId,
            RuntimeRoot = @"C:\KSwordSandbox\out",
            RootPath = @"C:\KSwordSandbox\out\artifacts",
            ImportRoot = @"C:\KSwordSandbox\out",
            Producer = "KSword.Sandbox.SmokeTests.SyntheticEndToEnd",
            Collections =
            [
                Collection("dropped-files", ArtifactKind.DroppedFile, "dropped-file", "dropped-file", "artifacts/dropped-files", "captured"),
                Collection("screenshots", ArtifactKind.Screenshot, "screenshot", "screenshot", "screenshots", "captured"),
                Collection("memory-dumps", ArtifactKind.MemoryDump, "memory-dump", "memory-dump", "memory-dumps", "captured"),
                Collection("driver-events", ArtifactKind.DriverEventsJsonLines, "telemetry", "driver-events", "driver-events.jsonl", "captured")
            ],
            Artifacts =
            [
                Artifact(ArtifactKind.DroppedFile, "ksword-e2e-drop.bin", "dropped-file", droppedRelativePath, "dropped-file", "dropped-files", @"C:\Users\Public\ksword-e2e-drop.bin"),
                Artifact(ArtifactKind.Screenshot, "after-run.bmp", "screenshot", screenshotRelativePath, "screenshot", "screenshots", @"C:\KSwordSandbox\out\screenshots\after-run.bmp"),
                Artifact(ArtifactKind.MemoryDump, "synthetic-pid4242.dmp", "memory-dump", memoryRelativePath, "memory-dump", "memory-dumps", @"C:\KSwordSandbox\out\memory-dumps\synthetic-pid4242.dmp"),
                Artifact(ArtifactKind.DriverEventsJsonLines, "driver-events.jsonl", "telemetry", "driver-events.jsonl", "driver-events", "driver-events", @"C:\KSwordSandbox\out\driver-events.jsonl")
            ]
        };

        var manifestPath = Path.Combine(guestRoot, "artifacts", "manifest.json");
        Directory.CreateDirectory(Path.GetDirectoryName(manifestPath) ?? guestRoot);
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, JsonOptions), cancellationToken);
    }

    private static ArtifactCollectionDescriptor Collection(string name, ArtifactKind kind, string category, string role, string relativePath, string status) =>
        new()
        {
            Name = name,
            Kind = kind,
            Category = category,
            EvidenceRole = role,
            RelativePath = relativePath,
            ImportPath = relativePath,
            Enabled = true,
            Implemented = true,
            Status = status
        };

    private static ArtifactDescriptor Artifact(
        ArtifactKind kind,
        string name,
        string category,
        string relativePath,
        string role,
        string collectionName,
        string guestPath) =>
        new()
        {
            Kind = kind,
            Name = name,
            Category = category,
            RelativePath = relativePath,
            SafeLink = relativePath.Replace('\\', '/'),
            EvidenceRole = role,
            CaptureState = "captured",
            GuestPath = guestPath,
            FullPath = guestPath,
            ImportPath = relativePath,
            CollectionName = collectionName,
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["origin"] = "synthetic-smoke",
                ["evidenceRole"] = role,
                ["collectionName"] = collectionName
            }
        };

    private static void AssertLiveSnapshotBeforeImport(SandboxJobService service, Guid jobId, string eventsPath)
    {
        var snapshot = service.GetLiveEvents(jobId, offset: 0, take: 4);
        SmokeAssert.True(snapshot.JobId == jobId, "Live snapshot should carry the requested job id before import.");
        SmokeAssert.True(snapshot.TotalEvents >= 10, "Live snapshot should include events.json, driver-events.jsonl, and partial JSONL parse diagnostics before import.");
        SmokeAssert.True(snapshot.Events.Count == 4, "Live snapshot should honor requested paging before import.");
        SmokeAssert.True(snapshot.NextOffset == 4, "Live snapshot should advance next offset before import.");
        SmokeAssert.True(snapshot.HasMore, "Live snapshot should report additional raw events before import.");
        SmokeAssert.True(snapshot.Sources.Any(source => string.Equals(source, eventsPath, StringComparison.OrdinalIgnoreCase)), "Live snapshot should list events.json before import.");
        SmokeAssert.True(snapshot.Sources.Any(source => string.Equals(Path.GetFileName(source), "driver-events.jsonl", StringComparison.OrdinalIgnoreCase)), "Live snapshot should list driver-events.jsonl before import.");
        SmokeAssert.True(snapshot.Sources.Any(source => string.Equals(Path.GetFileName(source), "partial-driver-events.jsonl", StringComparison.OrdinalIgnoreCase)), "Live snapshot should list partial JSONL live source before import.");
    }

    private static AnalysisReport AssertImportedReport(AnalysisJob imported, SyntheticUploadContract upload, string guestEventsPath)
    {
        SmokeAssert.True(imported.Status == AnalysisStatus.Completed, "Guest event import should complete the synthetic job.");
        SmokeAssert.True(string.Equals(imported.GuestEventsPath, guestEventsPath, StringComparison.OrdinalIgnoreCase), "Imported job should remember the primary guest events path.");
        SmokeAssert.True(File.Exists(imported.JsonReportPath), "Imported job should write refreshed report.json.");

        var report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(imported.JsonReportPath!), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Imported report.json should deserialize.");
        SmokeAssert.True(report.JobId == imported.JobId, "Imported report job id should match the job.");
        SmokeAssert.True(report.Status == AnalysisStatus.Completed, "Imported report status should be completed.");
        SmokeAssert.True(string.Equals(report.Sample.FullPath, upload.StoredPath, StringComparison.OrdinalIgnoreCase), "Imported report should retain uploaded sample path.");
        SmokeAssert.True(report.Events.Any(evt => evt.EventType == "submission.accepted" && string.Equals(evt.Path, upload.StoredPath, StringComparison.OrdinalIgnoreCase)), "Imported report should retain the upload/selection planning event.");
        SmokeAssert.True(report.Events.Any(evt => evt.EventType == "process.start" && evt.ProcessName == "powershell.exe"), "Imported report should contain synthetic guest process evidence.");
        SmokeAssert.True(report.Events.Any(evt => evt.EventType == "driver.file.create"), "Imported report should contain synthetic driver file evidence.");
        SmokeAssert.True(report.Events.Any(evt => evt.EventType == "r0collector.mockDriverEvent"), "Imported report should contain synthetic R0 collector evidence.");
        SmokeAssert.True(report.Events.Any(evt => evt.EventType == "screenshot.captured"), "Imported report should contain screenshot artifact evidence.");
        SmokeAssert.True(report.Events.Any(evt => evt.EventType == "memory_dump.captured"), "Imported report should contain memory dump artifact evidence.");
        var importEvent = report.Events.FirstOrDefault(evt => evt.EventType == "guest.events.imported");
        SmokeAssert.True(importEvent is not null, "Imported report should include guest.events.imported marker.");
        SmokeAssert.True(importEvent!.Data.TryGetValue("eventCount", out var eventCountText) && int.TryParse(eventCountText, out var importedEventCount) && importedEventCount == 9, "Guest import marker should count events.json plus driver-events.jsonl rows.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "script-interpreter"), "Synthetic process event should trigger script-interpreter rule.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "registry-change"), "Synthetic registry event should trigger registry-change rule.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "r0collector-mock-driver-event"), "Synthetic R0 mock event should trigger R0 collector rule.");
        SmokeAssert.True(report.Metrics.TryGetValue("events.total", out var totalEvents) && totalEvents >= 14, "Imported report metrics should count planning, runbook, guest, driver, and import events.");

        return report;
    }

    private static void AssertBilingualReports(AnalysisJob imported, AnalysisReport report)
    {
        SmokeAssert.True(File.Exists(imported.HtmlReportPath), "Imported job should write compatibility report.html.");
        SmokeAssert.True(File.Exists(imported.HtmlReportZhPath), "Imported job should write report.zh.html.");
        SmokeAssert.True(File.Exists(imported.HtmlReportEnPath), "Imported job should write report.en.html.");
        SmokeAssert.True(Path.GetFileName(imported.HtmlReportZhPath) == "report.zh.html", "Chinese report file name should be report.zh.html.");
        SmokeAssert.True(Path.GetFileName(imported.HtmlReportEnPath) == "report.en.html", "English report file name should be report.en.html.");

        var jobRelativeDropPath = $"guest/{report.JobId:N}/artifacts/dropped-files/ksword-e2e-drop.bin";
        var chineseHtml = File.ReadAllText(imported.HtmlReportZhPath!);
        var englishHtml = File.ReadAllText(imported.HtmlReportEnPath!);

        RequireContains(chineseHtml, "<html lang=\"zh-CN\">", "Chinese report should set zh-CN language metadata.");
        RequireContains(chineseHtml, "风险摘要", "Chinese report should include localized risk summary.");
        RequireContains(chineseHtml, "原始事件", "Chinese report should include localized raw event section.");
        RequireContains(chineseHtml, "driver-events.jsonl", "Chinese report should include driver JSONL evidence.");
        RequireContains(chineseHtml, "ksword-e2e-drop.bin", "Chinese report should include dropped-file evidence.");
        RequireContains(chineseHtml, jobRelativeDropPath, "Chinese report should link the synthetic dropped artifact using a safe relative path.");

        RequireContains(englishHtml, "<html lang=\"en\">", "English report should set English language metadata.");
        RequireContains(englishHtml, "Risk summary", "English report should include risk summary.");
        RequireContains(englishHtml, "Raw normalized events", "English report should include raw normalized events.");
        RequireContains(englishHtml, "Artifact links", "English report should include artifact links.");
        RequireContains(englishHtml, "R0 / driver events", "English report should include R0 / driver events.");
        RequireContains(englishHtml, "driver-events.jsonl", "English report should include driver JSONL evidence.");
        RequireContains(englishHtml, "ksword-e2e-drop.bin", "English report should include dropped-file evidence.");
        RequireContains(englishHtml, jobRelativeDropPath, "English report should link the synthetic dropped artifact using a safe relative path.");
        RequireNotContains(englishHtml, "href=\"D:\\", "English report should not href local absolute Windows paths.");
        RequireNotContains(englishHtml, "href=\"C:\\", "English report should not href guest absolute Windows paths.");
        RequireNotContains(englishHtml, "file://", "English report should not emit file:// artifact links.");
    }

    private static void AssertArtifactIndex(SandboxJobService service, AnalysisJob imported)
    {
        var index = service.BuildArtifactIndex(imported.JobId);
        SmokeAssert.True(index.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.GuestEventsJson && artifact.Name == "events.json"), "Artifact index should include events.json.");
        SmokeAssert.True(index.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.DriverEventsJsonLines && artifact.Name == "driver-events.jsonl"), "Artifact index should include driver-events.jsonl.");
        SmokeAssert.True(index.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.ArtifactManifest && artifact.Name == "manifest.json"), "Artifact index should include guest artifacts/manifest.json.");
        SmokeAssert.True(index.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.DroppedFile && artifact.Name == "ksword-e2e-drop.bin"), "Artifact index should include the synthetic dropped file.");
        SmokeAssert.True(index.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.Screenshot && artifact.Name == "after-run.bmp"), "Artifact index should include the synthetic screenshot.");
        SmokeAssert.True(index.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.MemoryDump && artifact.Name == "synthetic-pid4242.dmp"), "Artifact index should include the synthetic memory dump.");
        SmokeAssert.True(index.Collections.Any(collection => collection.Name == "dropped-files" && collection.Status == "captured"), "Artifact index should preserve dropped-files collection state.");

        var descriptor = service.ResolveDownloadableArtifact(imported.JobId, $"guest/{imported.JobId:N}/artifacts/dropped-files/ksword-e2e-drop.bin");
        SmokeAssert.True(descriptor.Kind == ArtifactKind.DroppedFile, "Dropped artifact should resolve through the safe relative selector.");
        SmokeAssert.True(File.Exists(descriptor.FullPath), "Resolved dropped artifact should exist under the job root.");
    }

    private static void AssertLiveUiContract(SmokeTestContext context, SandboxJobService service, Guid jobId, string eventsPath)
    {
        var snapshot = service.GetLiveEvents(jobId, offset: 0, take: 100);
        SmokeAssert.True(snapshot.TotalEvents >= 10, "Live UI snapshot should include guest, driver, and malformed partial JSONL rows.");
        SmokeAssert.True(
            snapshot.Events.Any(evt =>
                evt.EventType == "live.events.source_status" &&
                evt.Data.TryGetValue("sourceFileName", out var sourceFileName) &&
                string.Equals(sourceFileName, "partial-driver-events.jsonl", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.TryGetValue("partialLineCount", out var partialLineCount) &&
                partialLineCount == "1"),
            "Live UI snapshot should surface partial JSONL through a source-status diagnostic.");
        SmokeAssert.True(snapshot.Events.Any(evt => evt.EventType == "process.start"), "Live UI snapshot should include process events.");
        SmokeAssert.True(snapshot.Events.Any(evt => evt.EventType == "driver.file.create"), "Live UI snapshot should include driver events.");
        SmokeAssert.True(snapshot.Events.Any(evt => evt.EventType == "r0collector.mockDriverEvent"), "Live UI snapshot should include R0 collector events.");
        SmokeAssert.True(snapshot.Sources.Any(source => string.Equals(source, eventsPath, StringComparison.OrdinalIgnoreCase)), "Live UI snapshot should include the primary events.json source.");

        var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        SmokeAssert.True(root.TryGetProperty("jobId", out var jsonJobId) && Guid.Parse(jsonJobId.GetString() ?? string.Empty) == jobId, "Live UI JSON should expose camelCase jobId.");
        SmokeAssert.True(root.TryGetProperty("retrievedAt", out _), "Live UI JSON should expose retrievedAt.");
        SmokeAssert.True(root.TryGetProperty("totalEvents", out var totalEvents) && totalEvents.GetInt32() == snapshot.TotalEvents, "Live UI JSON should expose totalEvents.");
        SmokeAssert.True(root.TryGetProperty("nextOffset", out _), "Live UI JSON should expose nextOffset.");
        SmokeAssert.True(root.TryGetProperty("hasMore", out _), "Live UI JSON should expose hasMore.");
        SmokeAssert.True(root.TryGetProperty("sources", out var sources) && sources.ValueKind == JsonValueKind.Array, "Live UI JSON should expose sources array.");
        SmokeAssert.True(root.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array && events.GetArrayLength() >= 10, "Live UI JSON should expose events array.");
        var firstEvent = events.EnumerateArray().First();
        SmokeAssert.True(firstEvent.TryGetProperty("eventType", out _), "Live UI event JSON should expose eventType.");
        SmokeAssert.True(firstEvent.TryGetProperty("timestamp", out _), "Live UI event JSON should expose timestamp.");
        SmokeAssert.True(firstEvent.TryGetProperty("source", out _), "Live UI event JSON should expose source.");
        SmokeAssert.True(firstEvent.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object, "Live UI event JSON should expose data object.");

        var program = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Program.cs");
        var dashboard = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "DashboardExperiencePage.cs");
        var liveEventsPage = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "LiveEventsPage.cs");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/events/live\"", "Web source should expose the live polling endpoint used by the synthetic contract.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/events/stream\"", "Web source should expose the live SSE endpoint used by the synthetic contract.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/report/html\"", "Web source should expose served report HTML used by the synthetic contract.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/guest-events/import\"", "Web source should expose manual guest import used by the synthetic contract.");
        RequireContains(dashboard, "/api/files/upload/start", "Dashboard should expose the one-click upload/start path covered by the synthetic upload model.");
        RequireContains(dashboard, "/jobs/${encodeURIComponent(jobId)}/live-events", "Dashboard should link planned jobs to the live monitor page.");
        RequireContains(dashboard, "/report/html?lang=zh", "Dashboard should build Chinese served report links.");
        RequireContains(dashboard, "/report/html?lang=en", "Dashboard should build English served report links.");
        RequireContains(liveEventsPage, "/events/live", "Live monitor page should poll the live event endpoint.");
        RequireContains(liveEventsPage, "/events/stream", "Live monitor page should attempt the SSE stream endpoint.");
        RequireContains(liveEventsPage, "contextmenu", "Live monitor page should support right-click copy for operator evidence.");
    }

    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        return File.ReadAllText(Path.Combine(allSegments));
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    private static void RequireNotContains(string content, string unexpected, string message)
    {
        SmokeAssert.True(!content.Contains(unexpected, StringComparison.Ordinal), message);
    }

    private sealed record SyntheticUploadContract(
        string OriginalFileName,
        string StoredPath,
        long Length,
        string Sha256);
}

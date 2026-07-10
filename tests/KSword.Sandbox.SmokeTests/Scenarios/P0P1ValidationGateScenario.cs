using System.Diagnostics;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Aggregates P0/P1 release-gate contracts that must remain automatically
/// verifiable before a live demo. Inputs are repository paths and a temporary
/// runtime root; processing performs source/docs checks, renders a synthetic
/// report, and exercises repository policy in an isolated temporary git repo;
/// the scenario returns pass/fail metadata without touching product code.
/// </summary>
internal sealed class P0P1ValidationGateScenario : ISmokeTestScenario
{
    public string ScenarioId => "p0-p1.validation-gates";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        AssertWebUiLiveEndpointContract(context);
        AssertGuestEventsAndDriverJsonlImportContract(context);
        AssertHyperVScriptContract(context);
        AssertR0DriverCollectorPresenceAndAbiContract(context);
        AssertReportSectionContract();
        await AssertRepositoryPolicyContractAsync(context, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "P0/P1 WebUI live endpoints, guest JSON/JSONL import, Hyper-V scripts, R0 ABI/files, report sections, and repo policy are gated."
        };
    }

    /// <summary>
    /// Verifies the WebUI live endpoint route and payload contract. Inputs are
    /// repository paths; processing checks route source, WebUI consumers, route
    /// helpers, and the LiveEventSnapshot model; return value is none.
    /// </summary>
    private static void AssertWebUiLiveEndpointContract(SmokeTestContext context)
    {
        var program = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Program.cs");
        var dashboard = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "DashboardExperiencePage.cs");
        var routeCatalog = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Infrastructure", "WebRouteCatalog.cs");
        var analysisModels = ReadRepositoryText(context, "src", "KSword.Sandbox.Abstractions", "AnalysisModels.cs");

        RequireContains(program, "app.MapGet(\"/api/jobs/{jobId:guid}/events/live\"", "Web API must map the live polling endpoint.");
        RequireContains(program, "app.MapGet(\"/api/jobs/{jobId:guid}/events/stream\"", "Web API must map the SSE live endpoint.");
        RequireContains(program, "WriteLiveEventStreamAsync", "SSE endpoint must delegate to a stream writer.");
        RequireContains(program, "service.GetLiveEvents(jobId", "Live endpoints must read from the shared live-event service path.");
        RequireContains(program, "JsonSerializerDefaults.Web", "SSE snapshots must use the Web/camelCase JSON contract.");
        RequireContains(program, "event: snapshot", "SSE endpoint must emit named snapshot frames.");
        RequireContains(program, "text/event-stream", "SSE endpoint must use the event-stream media type.");
        RequireContains(program, "BuildLiveSourceSignature", "SSE endpoint must reset offsets when live source files change.");

        RequireContains(dashboard, "new EventSource(url)", "Dashboard must prefer the SSE EventSource live monitor.");
        RequireContains(dashboard, "/events/stream?offset=0&take=100&intervalMs=2000", "Dashboard must call the SSE endpoint with cursor controls.");
        RequireContains(dashboard, "/events/live?offset=${offset}&take=100", "Dashboard must keep the polling fallback endpoint wired.");
        RequireContains(dashboard, "liveEventSourceSignatures", "Dashboard must reset live cursors when event artifacts change.");
        RequireContains(dashboard, "snapshot.nextOffset", "Dashboard must honor the server cursor.");
        RequireContains(dashboard, "snapshot.sources", "Dashboard must display live source artifacts.");

        RequireContains(routeCatalog, "LiveEvents(Guid jobId)", "Route catalog must expose the polling route helper.");
        RequireContains(routeCatalog, "LiveEventStream(Guid jobId)", "Route catalog must expose the SSE route helper.");
        RequireContains(routeCatalog, "/events/live", "Route catalog must retain the live polling suffix.");
        RequireContains(routeCatalog, "/events/stream", "Route catalog must retain the live stream suffix.");

        foreach (var property in new[]
        {
            "JobId",
            "RetrievedAt",
            "TotalEvents",
            "NextOffset",
            "HasMore",
            "Sources",
            "Events"
        })
        {
            RequireContains(analysisModels, property, $"LiveEventSnapshot must expose {property}.");
        }
    }

    /// <summary>
    /// Verifies host import and guest-side driver JSONL merge contracts. Inputs
    /// are repository paths; processing reads source/docs for recursive JSONL
    /// discovery, parse-error preservation, dedupe, and report regeneration;
    /// return value is none.
    /// </summary>
    private static void AssertGuestEventsAndDriverJsonlImportContract(SmokeTestContext context)
    {
        var jobService = ReadRepositoryText(context, "src", "KSword.Sandbox.Core", "Jobs", "SandboxJobService.cs");
        var agentProgram = ReadRepositoryText(context, "guest", "KSword.Sandbox.Agent", "Program.cs");
        var driverReader = ReadRepositoryText(context, "guest", "KSword.Sandbox.Agent", "Output", "DriverJsonLinesReader.cs");
        var reportDoc = ReadRepositoryText(context, "docs", "report-schema.md");
        var jsonlDoc = ReadRepositoryText(context, "docs", "r0-jsonl-schema.md");

        RequireContains(jobService, "ImportGuestEvents(Guid jobId, string? eventsPath = null)", "Job service must expose explicit guest import.");
        RequireContains(jobService, "ResolveGuestEventsPath", "Guest import must locate collected events deterministically.");
        RequireContains(jobService, "LoadGuestEventsWithDriverJsonl", "Guest import must merge sibling driver JSONL.");
        RequireContains(jobService, "Directory.EnumerateFiles(searchRoot, \"*.jsonl\", SearchOption.AllDirectories)", "Guest import must recursively discover driver JSONL files.");
        RequireContains(jobService, "driver.parse_error", "Malformed JSONL rows must remain visible as parse-error evidence.");
        RequireContains(jobService, "EventKey", "Guest import must de-duplicate events when merging JSON and JSONL.");
        RequireContains(jobService, "guest.events.imported", "Report regeneration must include an import marker event.");
        RequireContains(jobService, "RegenerateReport", "Guest import must regenerate report.json/report.html after import.");
        RequireContains(jobService, "EnumerateLiveEventFiles", "Live endpoint must read events.json and JSONL artifacts without importing.");

        RequireContains(agentProgram, "--driver-events", "Guest Agent must accept the driver JSONL path.");
        RequireContains(agentProgram, "DriverJsonLinesReader", "Guest Agent must keep a dedicated driver JSONL read path.");
        RequireContains(agentProgram, "ReadDriverEvents(options.DriverEventsPath)", "Guest Agent must merge driver JSONL into guest output.");
        RequireContains(agentProgram, "driverJsonLinesReader.Read", "Guest Agent driver JSONL wrapper must delegate to DriverJsonLinesReader.");
        RequireContains(agentProgram, "events.json", "Guest Agent must continue writing canonical events.json.");
        RequireContains(agentProgram, "DriverEventsPath", "Guest Agent must consume the host-supplied driver JSONL path.");
        RequireContains(driverReader, "Read(string? path)", "Driver JSONL reader must expose a reader method.");
        RequireContains(driverReader, "JsonSerializer.Deserialize<SandboxEvent>", "Driver JSONL reader must parse normalized SandboxEvent rows.");
        RequireContains(driverReader, "driver.parse_error", "Driver JSONL reader must preserve malformed line evidence.");

        RequireContains(reportDoc, "events.json", "Report schema doc must describe imported guest events.");
        RequireContains(reportDoc, "driver-events.jsonl", "Report schema doc must describe driver JSONL import.");
        RequireContains(jsonlDoc, "driver.process", "R0 JSONL schema must include typed process rows.");
        RequireContains(jsonlDoc, "driver.file", "R0 JSONL schema must include typed file rows.");
        RequireContains(jsonlDoc, "driver.registry", "R0 JSONL schema must include typed registry rows.");
    }

    /// <summary>
    /// Verifies non-mutating Hyper-V script contracts. Inputs are repository
    /// paths; processing checks plan-first defaults, ShouldProcess gates,
    /// credential secrecy, PowerShell Direct, collection, and cleanup markers;
    /// return value is none.
    /// </summary>
    private static void AssertHyperVScriptContract(SmokeTestContext context)
    {
        var invokeScript = ReadRepositoryText(context, "scripts", "Invoke-HyperVE2E.ps1");
        var startScript = ReadRepositoryText(context, "scripts", "Start-SandboxHyperVJob.ps1");
        var collectScript = ReadRepositoryText(context, "scripts", "Collect-GuestOutputs.ps1");

        RequireContains(invokeScript, "SupportsShouldProcess", "Hyper-V orchestrator must support -WhatIf/-Confirm.");
        RequireContains(invokeScript, "PlanOnly", "Hyper-V orchestrator must default to plan-only review.");
        RequireContains(invokeScript, "willMutateVm", "Hyper-V plan must expose whether VM mutation will happen.");
        RequireContains(invokeScript, "safeDefault = $true", "Hyper-V plan must record the safe default.");
        RequireContains(invokeScript, "noVmMutationWhenPlanOnly", "Hyper-V plan must record plan-only non-mutation.");
        RequireContains(invokeScript, "secretValuePrinted = $false", "Hyper-V plan must document that secrets are not printed.");
        RequireContains(invokeScript, "Test-IsAdministrator", "Live Hyper-V execution must require an elevated shell.");
        RequireContains(invokeScript, "Start-SandboxHyperVJob.ps1", "Hyper-V orchestrator must delegate live start.");
        RequireContains(invokeScript, "Collect-GuestOutputs.ps1", "Hyper-V orchestrator must delegate collection/cleanup.");
        RequireContains(invokeScript, "driver-events.jsonl", "Hyper-V plan must model the driver JSONL artifact path.");

        RequireContains(startScript, "if ((-not [bool]$Live) -or [bool]$WhatIfPreference)", "Start script must be non-mutating by default and under -WhatIf.");
        RequireContains(startScript, "Restore-VMSnapshot", "Start script must restore the clean checkpoint in live mode.");
        RequireContains(startScript, "Copy-VMFile", "Start script must copy the sample through Guest Service Interface.");
        RequireContains(startScript, "Copy-Item -ToSession", "Start script must stage payload through PowerShell Direct.");
        RequireContains(startScript, "New-PSSession -VMName", "Start script must use a VM PowerShell Direct session.");
        RequireContains(startScript, "--driver-events", "Start script must pass driver JSONL arguments to the guest agent.");
        RequireContains(startScript, "--r0collector", "Start script must pass the R0Collector sidecar when enabled.");
        RequireContains(startScript, "No VM command was executed", "Start script must fail safely before mutation when prerequisites fail.");

        RequireContains(collectScript, "if ((-not [bool]$Live) -or [bool]$WhatIfPreference)", "Collect script must be non-mutating by default and under -WhatIf.");
        RequireContains(collectScript, "agent.pid", "Collect script must wait on the guest agent pid marker.");
        RequireContains(collectScript, "agent.exit", "Collect script must validate the guest agent exit marker.");
        RequireContains(collectScript, "Copy-Item -FromSession", "Collect script must collect guest output through PowerShell Direct.");
        RequireContains(collectScript, "driver-events.jsonl", "Collect script must preserve driver JSONL artifacts.");
        RequireContains(collectScript, "Stop-VM", "Collect script must power down the VM during cleanup.");
        RequireContains(collectScript, "Restore-VMSnapshot", "Collect script must restore the clean checkpoint after cleanup.");
        RequireContains(collectScript, "cleanupErrors", "Collect script must persist cleanup failures.");
    }

    /// <summary>
    /// Verifies R0 source/project file presence and public ABI strings. Inputs
    /// are repository paths; processing checks driver, collector, project, and
    /// documentation files; return value is none.
    /// </summary>
    private static void AssertR0DriverCollectorPresenceAndAbiContract(SmokeTestContext context)
    {
        var driverRoot = Path.Combine(context.RepositoryRoot, "driver", "KSword.Sandbox.Driver");
        var collectorRoot = Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.R0Collector");
        var driverProject = ReadText(Path.Combine(driverRoot, "KSword.Sandbox.Driver.vcxproj"));
        var collectorProject = ReadText(Path.Combine(collectorRoot, "KSword.Sandbox.R0Collector.vcxproj"));
        var abiHeader = ReadText(Path.Combine(driverRoot, "include", "KSwordSandboxDriverIoctl.h"));
        var abiGuards = ReadText(Path.Combine(driverRoot, "src", "Common", "AbiGuards.c"));
        var controlDevice = ReadText(Path.Combine(driverRoot, "src", "Device", "ControlDevice.c"));
        var eventParser = ReadText(Path.Combine(collectorRoot, "src", "EventParser.cpp"));
        var ioctlClient = ReadText(Path.Combine(collectorRoot, "src", "IoctlClient.cpp"));
        var runtimeLoop = ReadText(Path.Combine(collectorRoot, "src", "RuntimeLoop.cpp"));

        foreach (var relativePath in new[]
        {
            "include\\KSwordSandboxDriverIoctl.h",
            "src\\Common\\AbiGuards.c",
            "src\\Core\\DriverEntry.c",
            "src\\Device\\ControlDevice.c",
            "src\\Eventing\\EventQueue.c",
            "src\\Producers\\File\\FileFilter.c",
            "src\\Producers\\Process\\ProcessMonitor.c",
            "src\\Producers\\Registry\\RegistryMonitor.c",
            "src\\Producers\\Network\\NetworkMonitor.c"
        })
        {
            var path = Path.Combine(driverRoot, relativePath);
            RequireFile(path);
            RequireContains(driverProject, relativePath, $"{relativePath} must be included in the driver project.");
        }

        RequireFile(Path.Combine(collectorRoot, "src", "Common.h"));
        RequireContains(collectorProject, "src\\Common.h", "Common.h must be included by R0Collector.");
        foreach (var module in new[]
        {
            "Options",
            "IoctlClient",
            "EventParser",
            "JsonWriter",
            "RuntimeLoop",
            "SyntheticMode"
        })
        {
            RequireFile(Path.Combine(collectorRoot, "src", module + ".h"));
            RequireFile(Path.Combine(collectorRoot, "src", module + ".cpp"));
            RequireContains(collectorProject, $"src\\{module}.cpp", $"{module}.cpp must be compiled by R0Collector.");
            RequireContains(collectorProject, $"src\\{module}.h", $"{module}.h must be included by R0Collector.");
        }

        foreach (var abiString in new[]
        {
            "KSWORD_SANDBOX_ABI_VERSION_MAJOR",
            "KSWORD_SANDBOX_ABI_VERSION_MINOR",
            "KSWORD_SANDBOX_INTERFACE_VERSION",
            "KSWORD_SANDBOX_EVENT_HEADER_VERSION",
            "KSWORD_SANDBOX_EVENT_HEADER",
            "KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE",
            "IOCTL_KSWORD_SANDBOX_GET_HEALTH",
            "IOCTL_KSWORD_SANDBOX_POLL",
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES",
            "IOCTL_KSWORD_SANDBOX_GET_STATUS",
            "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK",
            "KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD",
            "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS",
            "KSWORD_SANDBOX_PRODUCER_FLAG_FILE",
            "KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY",
            "KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK"
        })
        {
            RequireContains(abiHeader, abiString, $"Driver ABI header must expose {abiString}.");
        }

        foreach (var payload in new[]
        {
            "KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD",
            "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD"
        })
        {
            RequireContains(abiGuards, $"sizeof({payload}) <=", $"ABI guard must bound {payload}.");
        }

        RequireContains(controlDevice, "case IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES", "Control device must route capabilities IOCTL.");
        RequireContains(controlDevice, "case IOCTL_KSWORD_SANDBOX_GET_STATUS", "Control device must route status IOCTL.");
        RequireContains(controlDevice, "case IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK", "Control device must route producer-mask IOCTL.");
        RequireContains(ioctlClient, "IOCTL_KSWORD_SANDBOX_GET_HEALTH", "R0Collector must probe driver health.");
        RequireContains(ioctlClient, "IOCTL_KSWORD_SANDBOX_POLL", "R0Collector must poll for queued driver events.");
        RequireContains(ioctlClient, "IOCTL_KSWORD_SANDBOX_READ_EVENTS", "R0Collector must drain READ_EVENTS.");
        RequireContains(ioctlClient, "request.Flags = options.enableMaskSpecified ? options.enableMask : 0", "R0Collector must pass producer enable mask to READ_EVENTS.");
        RequireContains(runtimeLoop, "r0collector.deviceOpened", "R0Collector must emit lifecycle rows when driver mode opens.");

        foreach (var eventType in new[]
        {
            "driver.process",
            "image.load",
            "driver.file",
            "driver.registry",
            "driver.network",
            "driver.started"
        })
        {
            RequireContains(eventParser, eventType, $"R0Collector parser must expose {eventType}.");
        }

        foreach (var payloadSchema in new[]
        {
            "payloadSchema",
            "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD"
        })
        {
            RequireContains(eventParser, payloadSchema, $"R0Collector parser must emit {payloadSchema} metadata.");
        }
    }

    /// <summary>
    /// Renders a synthetic report and verifies the operator-facing sections.
    /// Inputs are none; processing uses the production renderer with synthetic
    /// normalized events; return value is none.
    /// </summary>
    private static void AssertReportSectionContract()
    {
        var processEvent = new SandboxEvent
        {
            EventType = "process.start",
            Source = "guest",
            ProcessName = "powershell.exe",
            ProcessId = 4242,
            ParentProcessId = 1000,
            CommandLine = "powershell -NoProfile -ExecutionPolicy Bypass",
            Path = @"C:\KSwordSandbox\incoming\sample.exe"
        };
        var report = new AnalysisReport
        {
            JobId = Guid.NewGuid(),
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "sample.exe",
                FullPath = @"D:\Temp\KSwordSandbox\samples\sample.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234ABCD",
                SizeBytes = 4096
            },
            Events =
            [
                processEvent,
                new SandboxEvent
                {
                    EventType = "file.created",
                    Source = "guest",
                    ProcessId = 4242,
                    Path = @"C:\Users\Sandbox\AppData\Local\Temp\drop.bin"
                },
                new SandboxEvent
                {
                    EventType = "registry.set",
                    Source = "driver",
                    ProcessId = 4242,
                    Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Smoke"
                },
                new SandboxEvent
                {
                    EventType = "network.tcp",
                    Source = "guest",
                    ProcessId = 4242,
                    Data =
                    {
                        ["remoteAddress"] = "203.0.113.10",
                        ["remotePort"] = "443"
                    }
                },
                new SandboxEvent
                {
                    EventType = "driver.file",
                    Source = "r0collector",
                    ProcessId = 4242,
                    Path = @"\Device\HarddiskVolume3\Temp\drop.bin",
                    Data =
                    {
                        ["payloadSchema"] = "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD"
                    }
                }
            ],
            Findings =
            [
                new BehaviorFinding
                {
                    RuleId = "p0p1-smoke-rule",
                    Title = "Synthetic P0/P1 behavior",
                    Severity = "medium",
                    MitreTechniqueId = "T1059",
                    MitreTechniqueName = "Command and Scripting Interpreter",
                    Summary = "Synthetic report section coverage.",
                    Evidence = [processEvent]
                }
            ],
            Metrics =
            {
                ["events.total"] = 5,
                ["findings.total"] = 1
            }
        };

        var html = new HtmlReportRenderer().Render(report);
        foreach (var (id, title) in new[]
        {
            ("risk", "Risk summary"),
            ("behavior", "Behavior detections"),
            ("mitre", "Multi-dimensional / MITRE"),
            ("rules", "Engine and rule hits"),
            ("static", "Static analysis"),
            ("dynamic", "Dynamic analysis"),
            ("artifacts", "Artifact links"),
            ("timeline", "Timeline"),
            ("process", "Process details"),
            ("files", "Dropped files"),
            ("registry", "Registry behavior"),
            ("network", "Network behavior"),
            ("failure", "Failure reasons"),
            ("events", "Raw normalized events")
        })
        {
            RequireContains(html, $"href=\"#{id}\"", $"Report table of contents must link to {title}.");
            RequireContains(html, $"id=\"{id}\"", $"Report must render the {title} section.");
            RequireContains(html, title, $"Report must show the {title} heading.");
        }

        RequireContains(html, "data-copy", "Report sections must expose copyable evidence fields.");
        RequireContains(html, "contextmenu", "Report must support right-click copy.");
        RequireContains(html, "Copy event", "Report raw evidence rows must include explicit copy actions.");
        RequireContains(html, "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD", "Report must preserve R0 payload-schema evidence in raw events.");
    }

    /// <summary>
    /// Exercises repository policy in a temporary git repository. Inputs are the
    /// real repository context and cancellation token; processing copies only
    /// the policy script, creates allowed and forbidden candidate files, and
    /// verifies pass/fail exit codes; return value is a completed task.
    /// </summary>
    private static async Task AssertRepositoryPolicyContractAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var sourcePolicy = Path.Combine(context.RepositoryRoot, "scripts", "Test-RepositoryPolicy.ps1");
        RequireFile(sourcePolicy);

        var tempRoot = Path.Combine(context.RuntimeRoot, "repo-policy", Guid.NewGuid().ToString("N"));
        var tempScripts = Path.Combine(tempRoot, "scripts");
        Directory.CreateDirectory(tempScripts);
        File.Copy(sourcePolicy, Path.Combine(tempScripts, "Test-RepositoryPolicy.ps1"));

        var gitInit = await RunProcessAsync(
            "git",
            ["init"],
            tempRoot,
            cancellationToken);
        SmokeAssert.True(gitInit.ExitCode == 0, $"Temporary repo init failed: {gitInit.CombinedOutput}");

        var srcRoot = Path.Combine(tempRoot, "src");
        var binRoot = Path.Combine(tempRoot, "bin", "Debug");
        Directory.CreateDirectory(srcRoot);
        Directory.CreateDirectory(binRoot);
        await File.WriteAllTextAsync(Path.Combine(tempRoot, "README.md"), "ok", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(srcRoot, "Allowed.cs"), "namespace SmokePolicy { internal sealed class Allowed { } }", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(binRoot, "blocked.exe"), "not a real executable", cancellationToken);

        var policyScript = Path.Combine(tempScripts, "Test-RepositoryPolicy.ps1");
        var shell = OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh";
        var rejectResult = await RunProcessAsync(
            shell,
            ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", policyScript],
            tempRoot,
            cancellationToken);
        SmokeAssert.True(rejectResult.ExitCode != 0, "Repository policy must reject forbidden binary/build-output candidates.");
        SmokeAssert.True(
            rejectResult.CombinedOutput.Contains("blocked.exe", StringComparison.OrdinalIgnoreCase) ||
            rejectResult.CombinedOutput.Contains("Forbidden path or extension", StringComparison.OrdinalIgnoreCase),
            $"Repository policy rejection should name the forbidden candidate. Output: {rejectResult.CombinedOutput}");

        File.Delete(Path.Combine(binRoot, "blocked.exe"));
        var passResult = await RunProcessAsync(
            shell,
            ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", policyScript],
            tempRoot,
            cancellationToken);
        SmokeAssert.True(passResult.ExitCode == 0, $"Repository policy should pass after forbidden files are removed. Output: {passResult.CombinedOutput}");

        foreach (var expected in new[]
        {
            ".vhdx",
            ".exe",
            ".sys",
            ".pfx",
            "/bin/",
            "/obj/",
            "runtime/",
            "reports/",
            "samples/"
        })
        {
            RequireContains(ReadText(sourcePolicy), expected, $"Repository policy must continue blocking {expected}.");
        }
    }

    /// <summary>
    /// Runs a child process with captured output. Inputs are executable name,
    /// arguments, working directory, and cancellation token; processing waits
    /// for exit; return value contains exit code and combined output.
    /// </summary>
    private static async Task<ProcessRunResult> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        return new ProcessRunResult(process.ExitCode, string.Concat(stdout, stderr));
    }

    /// <summary>
    /// Reads a required repository file as text. Inputs are context and relative
    /// path segments; processing joins the path under RepositoryRoot; return
    /// value is the complete file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        return ReadText(Path.Combine(allSegments));
    }

    /// <summary>
    /// Reads one required text file. Inputs are a path; processing asserts
    /// existence and reads the file; return value is file text.
    /// </summary>
    private static string ReadText(string path)
    {
        RequireFile(path);
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires one file to exist. Inputs are a path; processing throws on
    /// absence; return value is none.
    /// </summary>
    private static void RequireFile(string path)
    {
        SmokeAssert.True(File.Exists(path), $"Required P0/P1 validation file is missing: {path}");
    }

    /// <summary>
    /// Requires a literal substring to be present. Inputs are content, expected
    /// text, and failure message; processing uses ordinal matching; return
    /// value is none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Captures a child-process result. Inputs are exit code and output;
    /// processing stores immutable data; return value is the record itself.
    /// </summary>
    private sealed record ProcessRunResult(int ExitCode, string CombinedOutput);
}

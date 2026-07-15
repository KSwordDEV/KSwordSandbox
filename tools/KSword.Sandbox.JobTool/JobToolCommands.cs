using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Execution;
using System.Text.Json;

internal static partial class ProgramMain
{
    private static int PlanJob(JobToolOptions options)
    {
        var context = CreateContext(options);
        var sampleOption = GetOption(options, "sample", GetOption(options, "sample-path", string.Empty));
        if (string.IsNullOrWhiteSpace(sampleOption))
        {
            throw new ArgumentException("plan 缺少必需参数 --sample <path>。/ Missing required --sample <path> for plan.");
        }

        var samplePath = RequireExistingFile(sampleOption, "sample");
        var duration = ParseNonNegativeInt(
            GetOption(options, "duration", GetOption(options, "duration-seconds", context.Config.Analysis.DefaultDurationSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture))),
            "duration");
        var guestReadyTimeoutSeconds = ParsePositiveInt(
            GetOption(options, "guest-ready-timeout-seconds", context.Config.Analysis.GuestReadyTimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            "guest-ready-timeout-seconds");
        var displayName = GetOption(options, "display-name", Path.GetFileName(samplePath));
        var provider = ParseVirtualizationProvider(GetOption(options, "provider", context.Config.Virtualization.Provider.ToString()));
        ValidateProviderResourceOverrides(options, context.Config, provider);
        var configuredVmName = GetConfiguredVmName(context.Config, provider);
        var configuredSnapshotName = GetConfiguredSnapshotName(context.Config, provider);
        var machineDefinitionPath = GetProviderMachineDefinitionPath(options, context.Config, provider);
        var service = CreateService(context);
        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DisplayName = displayName,
            DurationSeconds = duration,
            GuestReadyTimeoutSeconds = guestReadyTimeoutSeconds,
            DryRun = true,
            Provider = provider,
            GoldenVmName = GetOption(options, "vm", configuredVmName),
            GoldenSnapshotName = GetOption(options, "baseline", GetOption(options, "checkpoint", configuredSnapshotName)),
            MachineDefinitionPath = machineDefinitionPath,
            QemuDiskFormat = provider is VirtualizationProvider.Qemu
                ? GetOption(options, "qemu-disk-format", context.Config.Qemu.DiskFormat)
                : null,
            GuestUserName = GetOption(options, "guest-user", context.Config.Guest.UserName),
            GuestWorkingDirectory = GetOption(options, "guest-root", context.Config.Guest.WorkingDirectory),
            GuestPayloadRoot = GetOption(options, "guest-payload-root", context.Config.Paths.GuestPayloadRoot),
            UseMockCollector = GetNullableBool(options, "use-mock-collector")
        });

        var jobRoot = Path.Combine(ResolveRuntimeRoot(options, context.Config), "jobs", job.JobId.ToString("N"));
        var artifactIndexPath = Path.Combine(jobRoot, HostArtifactIndexBuilder.IndexFileName);
        var planPath = ResolvePlanOutputPath(options, context.RepositoryRoot);
        var effectiveProvider = job.Runbook?.Provider ?? provider;
        var effectiveVmName = job.Runbook?.TargetVmName ?? job.Submission.GoldenVmName;
        var effectiveBaselineName = job.Runbook?.BaselineName ?? job.Submission.GoldenSnapshotName;
        var effectiveMachineDefinitionPath = job.Runbook?.MachineDefinitionPath ?? job.Submission.MachineDefinitionPath;
        var effectiveQemuDiskFormat = job.Runbook?.QemuDiskFormat ?? job.Submission.QemuDiskFormat;
        var result = new
        {
            contractVersion = 1,
            kind = "KSwordSandbox.PlanResult",
            command = "plan",
            status = job.Status.ToString(),
            jobId = job.JobId,
            jobRoot,
            samplePath,
            displayName,
            durationSeconds = duration,
            guestReadyTimeoutSeconds,
            provider = effectiveProvider.ToString(),
            vmName = effectiveVmName,
            baselineName = effectiveBaselineName,
            checkpointName = effectiveBaselineName,
            machineDefinitionPath = effectiveMachineDefinitionPath,
            qemuDiskFormat = effectiveQemuDiskFormat,
            runbookStepCount = job.Runbook?.Steps.Count,
            jsonReportPath = job.JsonReportPath,
            htmlReportPath = job.HtmlReportPath,
            htmlReportZhPath = job.HtmlReportZhPath,
            htmlReportEnPath = job.HtmlReportEnPath,
            artifactIndexPath,
            planPath,
            vmAction = "none",
            operatorMessage = "已生成干跑计划产物，未启动或修改 VM。/ Dry-run plan artifacts were generated without starting or mutating a VM.",
            messages = job.Messages,
            secretValuePrinted = false
        };

        if (!string.IsNullOrWhiteSpace(planPath))
        {
            WriteJsonFile(planPath, result);
        }

        if (GetBool(options, "json"))
        {
            WriteJson(result);
            return 0;
        }

        Console.WriteLine("计划 / KSword Sandbox plan");
        Console.WriteLine($"任务 ID / Job ID: {job.JobId:D}");
        Console.WriteLine($"状态 / Status: {FormatStatusForHuman(job.Status.ToString())}");
        Console.WriteLine("VM 操作 / VM action: 无 / none");
        Console.WriteLine($"样本 / Sample: {Safe(samplePath)}");
        Console.WriteLine($"虚拟化后端 / Provider: {effectiveProvider}");
        Console.WriteLine($"VM: {Safe(effectiveVmName)}");
        Console.WriteLine($"干净基线 / Clean baseline: {Safe(effectiveBaselineName)}");
        if (effectiveProvider is not VirtualizationProvider.HyperV)
        {
            Console.WriteLine($"虚拟机定义 / Machine definition: {Safe(effectiveMachineDefinitionPath)}");
        }
        if (effectiveProvider is VirtualizationProvider.Qemu)
        {
            Console.WriteLine($"QEMU 磁盘格式 / Disk format: {Safe(effectiveQemuDiskFormat)}");
        }
        Console.WriteLine($"任务目录 / Job root: {Safe(jobRoot)}");
        if (!string.IsNullOrWhiteSpace(planPath))
        {
            Console.WriteLine($"计划结果 / Plan result: {FormatPathForHuman(planPath)}");
        }
        Console.WriteLine($"JSON 报告 / Report JSON: {FormatPathForHuman(job.JsonReportPath)}");
        Console.WriteLine($"HTML 报告 / Report HTML: {FormatPathForHuman(job.HtmlReportPath)}");
        Console.WriteLine($"运行步骤 / Runbook steps: {job.Runbook?.Steps.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "未知 / unknown"}");
        return 0;
    }

    private static async Task<int> ExecuteJobAsync(JobToolOptions options)
    {
        var context = CreateContext(options);
        var sampleOption = GetOption(options, "sample", GetOption(options, "sample-path", string.Empty));
        if (string.IsNullOrWhiteSpace(sampleOption))
        {
            throw new ArgumentException("execute 缺少必需参数 --sample <path>。/ Missing required --sample <path> for execute.");
        }

        var samplePath = RequireExistingFile(sampleOption, "sample");
        var duration = ParseNonNegativeInt(
            GetOption(options, "duration", GetOption(options, "duration-seconds", context.Config.Analysis.DefaultDurationSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture))),
            "duration");
        var guestReadyTimeoutSeconds = ParsePositiveInt(
            GetOption(options, "guest-ready-timeout-seconds", context.Config.Analysis.GuestReadyTimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            "guest-ready-timeout-seconds");
        var stepTimeoutSeconds = ParseNonNegativeInt(GetOption(options, "step-timeout-seconds", "1800"), "step-timeout-seconds");
        var displayName = GetOption(options, "display-name", Path.GetFileName(samplePath));
        var provider = ParseVirtualizationProvider(GetOption(options, "provider", context.Config.Virtualization.Provider.ToString()));
        ValidateProviderResourceOverrides(options, context.Config, provider);
        var live = GetBool(options, "live");
        if (live && stepTimeoutSeconds > 0 && stepTimeoutSeconds < guestReadyTimeoutSeconds)
        {
            throw new ArgumentException(
                $"--step-timeout-seconds ({stepTimeoutSeconds}) 不能小于 --guest-ready-timeout-seconds ({guestReadyTimeoutSeconds})；否则 guest transport 等待会被提前终止。/ Step timeout must be zero (unlimited) or at least the guest readiness timeout.");
        }
        var importGuestEvents = !GetBool(options, "skip-guest-import") && !GetBool(options, "no-import-guest-events");
        var configuredVmName = GetConfiguredVmName(context.Config, provider);
        var configuredSnapshotName = GetConfiguredSnapshotName(context.Config, provider);
        var machineDefinitionPath = GetProviderMachineDefinitionPath(options, context.Config, provider);
        var service = CreateService(context);
        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DisplayName = displayName,
            DurationSeconds = duration,
            GuestReadyTimeoutSeconds = guestReadyTimeoutSeconds,
            DryRun = !live,
            Provider = provider,
            GoldenVmName = GetOption(options, "vm", configuredVmName),
            GoldenSnapshotName = GetOption(options, "baseline", GetOption(options, "checkpoint", configuredSnapshotName)),
            MachineDefinitionPath = machineDefinitionPath,
            QemuDiskFormat = provider is VirtualizationProvider.Qemu
                ? GetOption(options, "qemu-disk-format", context.Config.Qemu.DiskFormat)
                : null,
            GuestUserName = GetOption(options, "guest-user", context.Config.Guest.UserName),
            GuestWorkingDirectory = GetOption(options, "guest-root", context.Config.Guest.WorkingDirectory),
            GuestPayloadRoot = GetOption(options, "guest-payload-root", context.Config.Paths.GuestPayloadRoot),
            UseMockCollector = GetNullableBool(options, "use-mock-collector"),
            CollectDroppedFiles = GetNullableBool(options, "collect-dropped-files"),
            CaptureScreenshots = GetNullableBool(options, "capture-screenshots"),
            CaptureMemoryDumps = GetNullableBool(options, "capture-memory-dumps"),
            CapturePacketCapture = GetNullableBool(options, "capture-packet-capture")
        });

        if (job.Runbook is null)
        {
            throw new InvalidOperationException($"任务 {job.JobId:D} 没有可执行流程。/ Job does not have an executable runbook.");
        }

        var runbookEnvironment = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (live)
        {
            var secretName = string.IsNullOrWhiteSpace(context.Config.Guest.PasswordSecretName)
                ? "KSWORDBOX_GUEST_PASSWORD"
                : context.Config.Guest.PasswordSecretName.Trim();
            if (!TryLoadGuestSecretIntoProcess(secretName))
            {
                throw new InvalidOperationException($"实时分析需要环境变量 '{secretName}'；变量值不会被输出。/ Live execution requires environment variable '{secretName}'; its value is never printed.");
            }
            runbookEnvironment[secretName] = Environment.GetEnvironmentVariable(secretName, EnvironmentVariableTarget.Process);
        }

        string? lastProgressKey = null;
        var progressSink = new InlineProgress<SandboxRunbookProgressSnapshot>(snapshot =>
        {
            service.SaveRunbookProgressSnapshot(snapshot);
            if (GetBool(options, "json"))
            {
                return;
            }

            var progressKey = $"{snapshot.State}|{snapshot.CurrentStepIndex}|{snapshot.CompletedSteps}|{snapshot.ProgressPercent}";
            if (string.Equals(progressKey, lastProgressKey, StringComparison.Ordinal))
            {
                return;
            }

            lastProgressKey = progressKey;
            var current = string.IsNullOrWhiteSpace(snapshot.CurrentStepTitle)
                ? snapshot.Message
                : snapshot.CurrentStepTitle;
            Console.WriteLine($"[{snapshot.ProgressPercent,3}%] {Safe(snapshot.State)} | {Safe(current)}");
        });

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        SandboxRunbookExecutionResult execution;
        AnalysisJob updatedJob;
        var guestImportSucceeded = false;
        var guestImportSkipped = false;
        var guestImportFailed = false;
        string? guestImportMessage = null;
        try
        {
            execution = await new PowerShellRunbookExecutor().ExecuteAsync(
                job.Runbook,
                new SandboxRunbookExecutionOptions
                {
                    Mode = live ? SandboxRunbookExecutionMode.Live : SandboxRunbookExecutionMode.DryRun,
                    PowerShellExecutablePath = GetOption(options, "powershell", "powershell.exe"),
                    StepTimeout = stepTimeoutSeconds == 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(stepTimeoutSeconds),
                    WorkingDirectory = context.RepositoryRoot,
                    RequireElevatedPowerShell = true,
                    EnvironmentVariables = runbookEnvironment,
                    ProgressSink = progressSink
                },
                cancellation.Token).ConfigureAwait(false);
            updatedJob = service.SaveRunbookExecutionResult(job.JobId, execution);

            if (live && execution.Success)
            {
                if (!importGuestEvents)
                {
                    guestImportSkipped = true;
                    guestImportMessage = "来宾事件自动导入已按请求跳过。/ Guest event auto-import was skipped by request.";
                    updatedJob = service.RecordGuestImportSkipped(job.JobId, guestImportMessage);
                }
                else
                {
                    try
                    {
                        updatedJob = service.ImportGuestEvents(job.JobId);
                        guestImportSucceeded = updatedJob.Status == AnalysisStatus.Completed;
                        guestImportFailed = !guestImportSucceeded;
                        guestImportMessage = updatedJob.Messages.LastOrDefault();
                    }
                    catch (Exception ex) when (ex is DirectoryNotFoundException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException or JsonException)
                    {
                        guestImportFailed = true;
                        guestImportMessage = $"来宾事件自动导入失败：{ex.Message} / Guest event auto-import failed.";
                        updatedJob = service.RecordGuestImportFailure(job.JobId, guestImportMessage);
                    }
                }
            }
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }

        var jobRoot = Path.Combine(ResolveRuntimeRoot(options, context.Config), "jobs", job.JobId.ToString("N"));
        var failedStep = execution.WasCanceled
            ? execution.StepResults.FirstOrDefault(step =>
                !step.Success &&
                ((step.Message?.Contains("canceled", StringComparison.OrdinalIgnoreCase) ?? false) ||
                 (step.Message?.Contains("cancelled", StringComparison.OrdinalIgnoreCase) ?? false)))
            : execution.FailedStepIndex is int failedIndex
                ? execution.StepResults.FirstOrDefault(step => step.StepIndex == failedIndex)
                : execution.StepResults.LastOrDefault(step => !step.Success);
        var safeSteps = execution.StepResults.Select(step => new
        {
            step.StepIndex,
            step.StepId,
            step.Title,
            step.Success,
            step.Skipped,
            step.ExitCode,
            step.Duration,
            step.Message
        }).ToArray();
        var effectiveProvider = execution.Provider;
        var effectiveVmName = execution.TargetVmName;
        var effectiveBaselineName = execution.BaselineName ?? job.Runbook.BaselineName ?? job.Submission.GoldenSnapshotName;
        var effectiveMachineDefinitionPath = execution.MachineDefinitionPath ?? job.Runbook.MachineDefinitionPath ?? job.Submission.MachineDefinitionPath;
        var effectiveQemuDiskFormat = execution.QemuDiskFormat ?? job.Runbook.QemuDiskFormat ?? job.Submission.QemuDiskFormat;
        var result = new
        {
            contractVersion = 1,
            kind = "KSwordSandbox.ExecutionResult",
            command = "execute",
            status = updatedJob.Status.ToString(),
            jobId = job.JobId,
            jobRoot,
            provider = effectiveProvider.ToString(),
            vmName = effectiveVmName,
            baselineName = effectiveBaselineName,
            checkpointName = effectiveBaselineName,
            machineDefinitionPath = effectiveMachineDefinitionPath,
            qemuDiskFormat = effectiveQemuDiskFormat,
            mode = execution.Mode.ToString(),
            executionState = execution.Success ? "Completed" : execution.WasCanceled ? "Canceled" : "Failed",
            execution.WasCanceled,
            guestReadyTimeoutSeconds,
            stepTimeoutSeconds,
            execution.Success,
            execution.TotalSteps,
            execution.ExecutedSteps,
            execution.FailedStepIndex,
            failedStepId = failedStep?.StepId,
            failedStepTitle = failedStep?.Title,
            execution.Message,
            runbookExecutionPath = updatedJob.RunbookExecutionResultPath,
            guestEventsPath = updatedJob.GuestEventsPath,
            guestImportSucceeded,
            guestImportSkipped,
            guestImportFailed,
            guestImportMessage,
            jsonReportPath = updatedJob.JsonReportPath,
            htmlReportPath = updatedJob.HtmlReportPath,
            htmlReportZhPath = updatedJob.HtmlReportZhPath,
            htmlReportEnPath = updatedJob.HtmlReportEnPath,
            steps = safeSteps,
            secretValuePrinted = false
        };

        if (GetBool(options, "json"))
        {
            WriteJson(result);
        }
        else
        {
            Console.WriteLine("执行结果 / KSword Sandbox execution");
            Console.WriteLine($"JobId : {job.JobId:D}");
            Console.WriteLine($"Provider : {effectiveProvider}");
            Console.WriteLine($"VM : {Safe(effectiveVmName)}");
            Console.WriteLine($"Baseline : {Safe(effectiveBaselineName)}");
            if (effectiveProvider is not VirtualizationProvider.HyperV)
            {
                Console.WriteLine($"MachineDefinition : {Safe(effectiveMachineDefinitionPath)}");
            }
            if (effectiveProvider is VirtualizationProvider.Qemu)
            {
                Console.WriteLine($"QemuDiskFormat : {Safe(effectiveQemuDiskFormat)}");
            }
            Console.WriteLine($"Mode : {execution.Mode}");
            Console.WriteLine($"ExecutionState : {(execution.Success ? "Completed" : execution.WasCanceled ? "Canceled" : "Failed")}");
            Console.WriteLine($"Success : {execution.Success && !guestImportFailed}");
            Console.WriteLine($"Status : {updatedJob.Status}");
            if (!string.IsNullOrWhiteSpace(execution.Message))
            {
                Console.WriteLine($"Message : {Safe(execution.Message)}");
            }
            Console.WriteLine($"JobRoot : {Safe(jobRoot)}");
            Console.WriteLine($"RunbookExecutionPath : {FormatPathForHuman(updatedJob.RunbookExecutionResultPath)}");
            Console.WriteLine($"ReportJsonPath : {FormatPathForHuman(updatedJob.JsonReportPath)}");
            Console.WriteLine($"ReportHtmlPath : {FormatPathForHuman(updatedJob.HtmlReportPath)}");
            if (failedStep is not null)
            {
                Console.WriteLine($"FailedStep : {Safe(failedStep.StepId)} | {Safe(failedStep.Title)}");
            }

            if (!string.IsNullOrWhiteSpace(guestImportMessage))
            {
                Console.WriteLine($"GuestImport : {Safe(guestImportMessage)}");
            }
        }

        return execution.Success && !guestImportFailed ? 0 : 1;
    }

    private static bool TryLoadGuestSecretIntoProcess(string secretName)
    {
        var processValue = Environment.GetEnvironmentVariable(secretName, EnvironmentVariableTarget.Process);
        if (!string.IsNullOrWhiteSpace(processValue))
        {
            return true;
        }

        foreach (var scope in new[] { EnvironmentVariableTarget.User, EnvironmentVariableTarget.Machine })
        {
            try
            {
                var value = Environment.GetEnvironmentVariable(secretName, scope);
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                Environment.SetEnvironmentVariable(secretName, value, EnvironmentVariableTarget.Process);
                return true;
            }
            catch (System.Security.SecurityException)
            {
                // Continue to the next scope without exposing a secret value.
            }
        }

        return false;
    }

    private static VirtualizationProvider ParseVirtualizationProvider(string value)
    {
        if (Enum.TryParse<VirtualizationProvider>(value, ignoreCase: true, out var provider) && Enum.IsDefined(provider))
        {
            return provider;
        }

        throw new ArgumentException($"不支持虚拟化后端 '{value}'；应为 HyperV、VMware 或 Qemu。/ Unsupported provider '{value}'; expected HyperV, VMware, or Qemu.");
    }

    private static void ValidateProviderResourceOverrides(
        JobToolOptions options,
        SandboxConfig config,
        VirtualizationProvider provider)
    {
        var baseline = GetOption(options, "baseline", GetOption(options, "checkpoint", string.Empty));
        var genericMachinePath = GetOption(options, "machine-definition-path", string.Empty);
        var vmxPath = GetOption(options, "vmx-path", string.Empty);
        var diskImagePath = GetOption(options, "disk-image-path", string.Empty);
        var qemuDiskFormat = GetOption(options, "qemu-disk-format", string.Empty);
        var hasMachinePath = !string.IsNullOrWhiteSpace(genericMachinePath) ||
            !string.IsNullOrWhiteSpace(vmxPath) ||
            !string.IsNullOrWhiteSpace(diskImagePath);

        if (options.Values.ContainsKey("baseline") &&
            options.Values.ContainsKey("checkpoint") &&
            !string.Equals(
                GetOption(options, "baseline", string.Empty).Trim(),
                GetOption(options, "checkpoint", string.Empty).Trim(),
                StringComparison.Ordinal))
        {
            throw new ArgumentException("--baseline 与 legacy --checkpoint 不能指定不同值。/ --baseline and legacy --checkpoint cannot specify different values.");
        }

        if (provider is VirtualizationProvider.HyperV && hasMachinePath)
        {
            throw new ArgumentException("HyperV 不接受 machine-definition/vmx/disk-image 路径覆盖；请使用 --vm 选择 Hyper-V VM。/ HyperV does not accept a machine-definition path override.");
        }
        if (provider is VirtualizationProvider.VMware && !string.IsNullOrWhiteSpace(diskImagePath))
        {
            throw new ArgumentException("VMware 不接受 --disk-image-path；请使用 --machine-definition-path 或 --vmx-path。/ VMware requires a VMX path override.");
        }
        if (provider is VirtualizationProvider.Qemu && !string.IsNullOrWhiteSpace(vmxPath))
        {
            throw new ArgumentException("Qemu 不接受 --vmx-path；请使用 --machine-definition-path 或 --disk-image-path。/ Qemu requires a disk image path override.");
        }
        if (provider is not VirtualizationProvider.Qemu && !string.IsNullOrWhiteSpace(qemuDiskFormat))
        {
            throw new ArgumentException($"--qemu-disk-format 只适用于 Qemu，当前 provider 为 {provider}。/ --qemu-disk-format is valid only for Qemu.");
        }

        var providerSpecificPath = provider is VirtualizationProvider.VMware ? vmxPath : diskImagePath;
        if (!string.IsNullOrWhiteSpace(genericMachinePath) &&
            !string.IsNullOrWhiteSpace(providerSpecificPath) &&
            !string.Equals(genericMachinePath.Trim(), providerSpecificPath.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("通用 machine-definition 路径与 provider 专属路径不能指定不同值。/ Generic and provider-specific machine paths cannot disagree.");
        }

        if (provider is VirtualizationProvider.Qemu &&
            config.Qemu.UseOverlayDisk &&
            !string.IsNullOrWhiteSpace(baseline) &&
            !string.Equals(baseline.Trim(), "per-job-overlay", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("当前 QEMU profile 使用 per-job overlay；不能把 --baseline 当作内部 snapshot。请省略该参数、使用 per-job-overlay，或先关闭 qemu.useOverlayDisk。/ QEMU overlay mode does not accept an internal snapshot baseline override.");
        }
    }

    private static string GetConfiguredVmName(SandboxConfig config, VirtualizationProvider provider)
    {
        return provider switch
        {
            VirtualizationProvider.VMware => config.VMware.VmName,
            VirtualizationProvider.Qemu => config.Qemu.VmName,
            _ => config.HyperV.GoldenVmName
        };
    }

    private static string GetConfiguredSnapshotName(SandboxConfig config, VirtualizationProvider provider)
    {
        return provider switch
        {
            VirtualizationProvider.VMware => config.VMware.SnapshotName,
            VirtualizationProvider.Qemu => config.Qemu.UseOverlayDisk ? string.Empty : config.Qemu.SnapshotName,
            _ => config.HyperV.GoldenSnapshotName
        };
    }

    private static string? GetProviderMachineDefinitionPath(
        JobToolOptions options,
        SandboxConfig config,
        VirtualizationProvider provider)
    {
        return provider switch
        {
            VirtualizationProvider.VMware => GetOption(
                options,
                "vmx-path",
                GetOption(options, "machine-definition-path", config.VMware.VmxPath)),
            VirtualizationProvider.Qemu => GetOption(
                options,
                "disk-image-path",
                GetOption(options, "machine-definition-path", config.Qemu.DiskImagePath)),
            _ => null
        };
    }

    private static int RecoverJob(JobToolOptions options)
    {
        var context = CreateContext(options);
        var locator = ResolveJobLocator(options, context.Config, requireExisting: true);
        var summary = BuildJobSummary(locator.JobRoot, buildArtifactIndex: true);
        var resultFiles = ReadRecoveryResultFiles(locator.JobRoot);
        var writeIndex = GetBool(options, "write-index");
        var writeState = GetBool(options, "write-state");
        var rebuildReport = GetBool(options, "rebuild-report") || GetBool(options, "report");
        HostArtifactIndex? index = null;
        ArtifactDescriptor? writtenDescriptor = null;
        AnalysisJob? rebuiltJob = null;
        string? statePath = null;
        EventInputResolution? rebuildEventInput = null;
        string? reportRebuildDiagnosticsPath = null;

        if (writeIndex || rebuildReport)
        {
            var builder = new HostArtifactIndexBuilder();
            index = builder.Build(locator.JobId, locator.JobRoot);
            if (writeIndex)
            {
                writtenDescriptor = builder.WriteIndex(locator.JobId, locator.JobRoot);
            }
        }

        if (rebuildReport)
        {
            var runtimeRoot = ResolveServiceRuntimeRoot(options, context.Config, locator);
            var serviceContext = CreateContext(options, runtimeRoot);
            EnsureServiceJobRootMatchesLocator(serviceContext.Config, locator);
            var samplePath = ResolveSamplePath(options, locator.JobRoot);
            rebuildEventInput = ResolveEventInput(options, locator.JobRoot, locator.JobId, allowFailureSkeleton: true);
            var runbookExecutionPath = ResolveRunbookExecutionPath(options, locator.JobRoot);
            var duration = ParseNonNegativeInt(GetOption(options, "duration", GetOption(options, "duration-seconds", "120")), "duration");
            var provider = ResolvePersistedOrConfiguredProvider(options, serviceContext.Config, locator.JobRoot);
            ValidateProviderResourceOverrides(options, serviceContext.Config, provider);
            var vmName = ResolvePersistedOrConfiguredVmName(options, serviceContext.Config, locator.JobRoot, provider);
            var snapshotName = ResolvePersistedOrConfiguredSnapshotName(options, serviceContext.Config, locator.JobRoot, provider);
            var machineDefinitionPath = ResolvePersistedOrConfiguredMachineDefinitionPath(options, serviceContext.Config, locator.JobRoot, provider);
            var qemuDiskFormat = ResolvePersistedOrConfiguredQemuDiskFormat(options, serviceContext.Config, locator.JobRoot, provider);
            try
            {
                rebuiltJob = CreateService(serviceContext).ImportExternalRun(
                    locator.JobId,
                    new SandboxSubmission
                    {
                        SamplePath = samplePath,
                        DisplayName = GetOption(options, "display-name", Path.GetFileName(samplePath)),
                        DurationSeconds = duration,
                        DryRun = false,
                        Provider = provider,
                        GoldenVmName = vmName,
                        GoldenSnapshotName = snapshotName,
                        MachineDefinitionPath = machineDefinitionPath,
                        QemuDiskFormat = qemuDiskFormat
                    },
                    rebuildEventInput.Path,
                    runbookExecutionPath);
                reportRebuildDiagnosticsPath = WriteReportRebuildDiagnostics(
                    locator,
                    "recover",
                    samplePath,
                    rebuildEventInput,
                    runbookExecutionPath,
                    success: true,
                    message: "recover --rebuild-report regenerated report artifacts from existing files only.",
                    rebuiltJob: rebuiltJob,
                    provider: provider,
                    vmName: vmName,
                    baselineName: snapshotName,
                    machineDefinitionPath: machineDefinitionPath,
                    qemuDiskFormat: qemuDiskFormat);
            }
            catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or DirectoryNotFoundException or InvalidOperationException or JsonException or IOException or UnauthorizedAccessException or KeyNotFoundException or FormatException)
            {
                reportRebuildDiagnosticsPath = WriteReportRebuildDiagnostics(
                    locator,
                    "recover",
                    samplePath,
                    rebuildEventInput,
                    runbookExecutionPath,
                    success: false,
                    message: ex.Message,
                    provider: provider,
                    vmName: vmName,
                    baselineName: snapshotName,
                    machineDefinitionPath: machineDefinitionPath,
                    qemuDiskFormat: qemuDiskFormat);
                throw new InvalidOperationException($"恢复报告重建失败，诊断已写入 {reportRebuildDiagnosticsPath}。/ Recover report rebuild failed; diagnostics were written to {reportRebuildDiagnosticsPath}. {ex.Message}", ex);
            }
            summary = BuildJobSummary(locator.JobRoot, buildArtifactIndex: true);
        }

        var recoveryAssessment = BuildRecoveryAssessment(summary, resultFiles, rebuiltJob is not null);
        if (writeState)
        {
            statePath = Path.Combine(locator.JobRoot, "operator-recovery.json");
            var state = new
            {
                contractVersion = 1,
                kind = "KSwordSandbox.OperatorRecoveryState",
                jobId = locator.JobId,
                jobRoot = locator.JobRoot,
                generatedAtUtc = DateTimeOffset.UtcNow,
                recoveryAssessment,
                wroteArtifactIndex = writtenDescriptor is not null,
                rebuiltReport = rebuiltJob is not null,
                secretValuePrinted = false
            };
            File.WriteAllText(statePath, System.Text.Json.JsonSerializer.Serialize(state, JsonOptions));
        }

        var output = new
        {
            contractVersion = 1,
            kind = "KSwordSandbox.RecoveryResult",
            command = "recover",
            jobId = locator.JobId,
            jobRoot = locator.JobRoot,
            safeDefault = true,
            vmAction = "none",
            wroteState = writeState,
            statePath,
            wroteArtifactIndex = writtenDescriptor is not null,
            writtenDescriptor,
            rebuiltReport = rebuiltJob is not null,
            rebuiltStatus = rebuiltJob?.Status.ToString(),
            summary,
            resultFiles,
            recoveryAssessment,
            artifactIndexPath = Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName),
            reportRebuildDiagnosticsPath,
            rebuildEventInput,
            artifactCount = index?.Artifacts.Count ?? summary.ArtifactCount,
            collectionCount = index?.Collections.Count ?? summary.CollectionCount,
            secretValuePrinted = false
        };

        if (GetBool(options, "json"))
        {
            WriteJson(output);
            return 0;
        }

        Console.WriteLine("恢复检查 / KSword Sandbox recovery");
        Console.WriteLine($"任务 ID / Job ID: {locator.JobId:D}");
        Console.WriteLine($"任务目录 / Job root: {Safe(locator.JobRoot)}");
        Console.WriteLine("VM 操作 / VM action: 无 / none");
        Console.WriteLine($"虚拟化后端 / Provider: {Safe(summary.Provider)}");
        Console.WriteLine($"VM: {FormatTextOrNone(summary.TargetVmName)} | Baseline: {FormatTextOrNone(summary.BaselineName)}");
        if (!string.IsNullOrWhiteSpace(summary.MachineDefinitionPath))
        {
            Console.WriteLine($"虚拟机定义 / Machine definition: {Safe(summary.MachineDefinitionPath)}");
        }

        if (!string.IsNullOrWhiteSpace(summary.QemuDiskFormat))
        {
            Console.WriteLine($"QEMU 磁盘格式 / Disk format: {Safe(summary.QemuDiskFormat)}");
        }

        Console.WriteLine($"恢复状态 / Recovered state: {FormatRecoveryStateForHuman(recoveryAssessment.State)}");
        Console.WriteLine($"失败原因 / Failure reason: {FormatTextOrNone(recoveryAssessment.FailureReason)}");
        Console.WriteLine("建议操作 / Recommended actions:");
        foreach (var action in recoveryAssessment.RecommendedActions)
        {
            Console.WriteLine($"- {Safe(action)}");
        }

        return recoveryAssessment.HasBlockingFailure ? 1 : 0;
    }

    private static int CheckReadiness(JobToolOptions options)
    {
        var checks = new List<ReadinessCheck>();
        ToolContext? context = null;
        var repositoryRoot = ResolveRepositoryRoot(GetOption(options, "repo-root", string.Empty));
        var configPath = ResolveConfigPath(options, repositoryRoot);
        SandboxConfig? config = null;

        try
        {
            context = CreateContext(options);
            config = context.Config;
            checks.Add(ReadinessCheck.Passed("config-load", "配置加载 / Config load", true, $"配置已加载: {context.ConfigPath} / Config loaded from {context.ConfigPath}.", new Dictionary<string, object?>
            {
                ["repositoryRoot"] = context.RepositoryRoot,
                ["configPath"] = context.ConfigPath
            }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentException)
        {
            checks.Add(ReadinessCheck.Failed("config-load", "配置加载 / Config load", true, $"配置加载失败 / Config load failed: {ex.Message}", new Dictionary<string, object?>
            {
                ["repositoryRoot"] = repositoryRoot,
                ["configPath"] = configPath
            }));
        }

        config ??= new SandboxConfig();
        var runtimeRoot = ResolveRuntimeRoot(options, config);
        var rulesPath = Path.Combine(config.Paths.RulesDirectory, "behavior-rules.json");
        AddPathCheck(checks, "runtime-root", "运行目录 / Runtime root", runtimeRoot, required: false, expectDirectory: true);
        AddPathCheck(checks, "rules", "行为规则 / Behavior rules", rulesPath, required: true, expectDirectory: false);
        AddPathCheck(checks, "guest-payload-root", "来宾载荷目录 / Guest payload root", config.Paths.GuestPayloadRoot, required: false, expectDirectory: true);

        var sampleOption = GetOption(options, "sample", GetOption(options, "sample-path", string.Empty));
        if (!string.IsNullOrWhiteSpace(sampleOption))
        {
            AddPathCheck(checks, "sample", "样本文件 / Sample file", Path.GetFullPath(sampleOption), required: true, expectDirectory: false);
        }

        if (!string.IsNullOrWhiteSpace(GetOption(options, "job-id", string.Empty)) ||
            !string.IsNullOrWhiteSpace(GetOption(options, "job-root", string.Empty)))
        {
            try
            {
                var locator = ResolveJobLocator(options, config, requireExisting: true);
                checks.Add(ReadinessCheck.Passed("job-root", "任务目录 / Job root", true, $"任务目录存在: {locator.JobRoot} / Job root exists: {locator.JobRoot}", new Dictionary<string, object?>
                {
                    ["jobId"] = locator.JobId,
                    ["jobRoot"] = locator.JobRoot
                }));
                var summary = BuildJobSummary(locator.JobRoot, buildArtifactIndex: false);
                checks.Add(summary.JsonReportPath is not null
                    ? ReadinessCheck.Passed("job-report", "任务报告 / Job report", false, $"报告存在: {summary.JsonReportPath} / Report exists: {summary.JsonReportPath}")
                    : ReadinessCheck.Warning("job-report", "任务报告 / Job report", false, "未找到 report.json；收集 events 后可使用 report 或 recover --rebuild-report 重建。/ report.json is not present; use report/recover --rebuild-report after events are collected."));
                checks.Add(summary.GuestEventsPath is not null
                    ? ReadinessCheck.Passed("job-events", "任务事件 / Job events", false, $"事件文件存在: {summary.GuestEventsPath} / Events exist: {summary.GuestEventsPath}")
                    : ReadinessCheck.Warning("job-events", "任务事件 / Job events", false, "任务目录下未找到来宾事件文件。/ No guest events file was found under the job root."));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or DirectoryNotFoundException or System.Text.Json.JsonException)
            {
                checks.Add(ReadinessCheck.Failed("job-root", "任务目录 / Job root", true, $"任务目录检查失败 / Job root check failed: {ex.Message}"));
            }
        }

        var failed = checks.Count(check => check.Status == "Failed");
        var warnings = checks.Count(check => check.Status == "Warning");
        var failedRequired = checks.Count(check => check.Status == "Failed" && check.Required);
        var output = new
        {
            contractVersion = 1,
            kind = "KSwordSandbox.OperatorReadiness",
            command = "readiness",
            generatedAtUtc = DateTimeOffset.UtcNow,
            overallStatus = failed > 0 ? "Failed" : warnings > 0 ? "Warning" : "Passed",
            canPlan = checks.All(check => !check.Required || check.Status != "Failed"),
            canInspectExistingJobs = Directory.Exists(Path.Combine(runtimeRoot, "jobs")),
            liveVmMutatingChecksRun = false,
            runtimeRoot,
            jobsRoot = Path.Combine(runtimeRoot, "jobs"),
            configPath = context?.ConfigPath ?? configPath,
            repositoryRoot = context?.RepositoryRoot ?? repositoryRoot,
            counts = new
            {
                passed = checks.Count(check => check.Status == "Passed"),
                warning = warnings,
                failed,
                failedRequired
            },
            checks,
            remediationHints = checks
                .Where(check => check.Status != "Passed")
                .SelectMany(check => check.RemediationHints)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            secretValuePrinted = false
        };

        if (GetBool(options, "json"))
        {
            WriteJson(output);
            return failedRequired > 0 ? 1 : 0;
        }

        Console.WriteLine("操作端就绪检查 / KSword Sandbox operator readiness");
        Console.WriteLine($"总体 / Overall: {FormatReadinessStatusForHuman(output.overallStatus)}");
        Console.WriteLine($"运行目录 / Runtime root: {Safe(runtimeRoot)}");
        foreach (var check in checks)
        {
            Console.WriteLine($"- {FormatReadinessStatusForHuman(check.Status)} | {Safe(check.Name)} | {Safe(check.Message)}");
        }

        return failedRequired > 0 ? 1 : 0;
    }

    private static int ListJobs(JobToolOptions options)
    {
        var context = CreateContext(options);
        var runtimeRoot = ResolveRuntimeRoot(options, context.Config);
        var jobsRoot = Path.Combine(runtimeRoot, "jobs");
        var limit = ParseLimit(options, defaultValue: 100);
        var summaries = Directory.Exists(jobsRoot)
            ? Directory.EnumerateDirectories(jobsRoot)
                .Select(directory => BuildJobSummary(directory, buildArtifactIndex: false))
                .Where(summary => summary.IsCandidate)
                .OrderByDescending(summary => summary.LastWriteUtc ?? DateTimeOffset.MinValue)
                .ThenBy(summary => summary.JobRoot, StringComparer.OrdinalIgnoreCase)
                .Take(limit)
                .ToList()
            : [];

        if (GetBool(options, "json"))
        {
            WriteJson(new
            {
                contractVersion = 1,
                kind = "KSwordSandbox.JobList",
                command = "list",
                runtimeRoot,
                jobsRoot,
                exists = Directory.Exists(jobsRoot),
                count = summaries.Count,
                jobs = summaries,
                secretValuePrinted = false
            });
            return 0;
        }

        Console.WriteLine("任务列表 / KSword Sandbox jobs");
        Console.WriteLine($"运行目录 / Runtime root: {Safe(runtimeRoot)}");
        Console.WriteLine($"任务目录 / Jobs root: {Safe(jobsRoot)}");
        if (!Directory.Exists(jobsRoot))
        {
            Console.WriteLine("未找到 jobs 目录。/ No jobs directory found.");
            return 0;
        }

        if (summaries.Count == 0)
        {
            Console.WriteLine("未发现任务产物。/ No job artifacts found.");
            return 0;
        }

        foreach (var summary in summaries)
        {
            var id = summary.JobId?.ToString("D") ?? "未知 / unknown";
            Console.WriteLine($"- {id} | {Safe(summary.Provider)} | {FormatStatusForHuman(summary.Status)} | {FormatNameForHuman(summary.SampleName)}");
            Console.WriteLine($"  VM: {FormatTextOrNone(summary.TargetVmName)} | Baseline: {FormatTextOrNone(summary.BaselineName)}");
            Console.WriteLine($"  目录 / Root: {Safe(summary.JobRoot)}");
            Console.WriteLine($"  更新时间 / Updated: {FormatDate(summary.LastWriteUtc)} | 事件 / Events: {FormatNullable(summary.ReportEventCount)} | 命中 / Findings: {FormatNullable(summary.FindingCount)} | 已索引产物 / Indexed artifacts: {FormatNullable(summary.ArtifactCount)}");
        }

        Console.WriteLine("提示 / Tip: 使用 show-job 或 inspect-artifacts 查看详情；添加 --json 可输出机器可读 JSON。/ Use show-job or inspect-artifacts for details; add --json for machine-readable output.");
        return 0;
    }

    private static int ShowJob(JobToolOptions options)
    {
        var context = CreateContext(options);
        var locator = ResolveJobLocator(options, context.Config, requireExisting: true);
        var summary = BuildJobSummary(locator.JobRoot, buildArtifactIndex: true);
        var artifactIndexPath = Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName);
        var existingIndex = TryReadArtifactIndex(locator.JobRoot);

        if (GetBool(options, "json"))
        {
            WriteJson(new
            {
                contractVersion = 1,
                kind = "KSwordSandbox.JobDetails",
                command = "status",
                jobId = locator.JobId,
                jobRoot = locator.JobRoot,
                summary,
                artifactIndexPath,
                artifactIndexExists = File.Exists(artifactIndexPath),
                persistedArtifactCount = existingIndex?.Artifacts.Count,
                persistedCollectionCount = existingIndex?.Collections.Count,
                secretValuePrinted = false
            });
            return 0;
        }

        Console.WriteLine("任务详情 / KSword Sandbox job");
        Console.WriteLine($"任务 ID / Job ID: {locator.JobId:D}");
        Console.WriteLine($"状态 / Status: {FormatStatusForHuman(summary.Status)}");
        Console.WriteLine($"虚拟化后端 / Provider: {Safe(summary.Provider)}");
        Console.WriteLine($"VM: {FormatTextOrNone(summary.TargetVmName)}");
        Console.WriteLine($"干净基线 / Clean baseline: {FormatTextOrNone(summary.BaselineName)}");
        if (!string.IsNullOrWhiteSpace(summary.MachineDefinitionPath))
        {
            Console.WriteLine($"虚拟机定义 / Machine definition: {Safe(summary.MachineDefinitionPath)}");
        }

        if (!string.IsNullOrWhiteSpace(summary.QemuDiskFormat))
        {
            Console.WriteLine($"QEMU 磁盘格式 / Disk format: {Safe(summary.QemuDiskFormat)}");
        }

        Console.WriteLine($"样本 / Sample: {FormatNameForHuman(summary.SampleName)}");
        if (!string.IsNullOrWhiteSpace(summary.SampleSha256))
        {
            Console.WriteLine($"样本 SHA-256 / Sample SHA-256: {Safe(summary.SampleSha256)}");
        }

        if (!string.IsNullOrWhiteSpace(summary.SamplePath))
        {
            Console.WriteLine($"样本路径 / Sample path: {Safe(summary.SamplePath)}");
        }

        Console.WriteLine($"任务目录 / Job root: {Safe(locator.JobRoot)}");
        Console.WriteLine($"更新时间 / Updated: {FormatDate(summary.LastWriteUtc)}");
        Console.WriteLine($"JSON 报告 / Report JSON: {FormatPathForHuman(summary.JsonReportPath)}");
        Console.WriteLine($"HTML 报告 / Report HTML: {FormatPathForHuman(summary.HtmlReportPath)}");
        Console.WriteLine($"来宾事件 / Guest events: {FormatPathForHuman(summary.GuestEventsPath)}");
        Console.WriteLine($"运行记录 / Runbook execution: {FormatPathForHuman(summary.RunbookExecutionPath)}");
        Console.WriteLine($"运行进度 / Runbook progress: {FormatPathForHuman(summary.RunbookProgressPath)}");
        Console.WriteLine($"失败 skeleton / Failure skeleton: {FormatPathForHuman(summary.GuestOutputSkeletonPath)}");
        Console.WriteLine($"Start result / Start 结果: {FormatPathForHuman(summary.StartResultPath)}");
        Console.WriteLine($"Collect result / Collect 结果: {FormatPathForHuman(summary.CollectResultPath)}");
        Console.WriteLine($"重建诊断 / Rebuild diagnostics: {FormatPathForHuman(summary.ReportRebuildDiagnosticsPath)}");
        Console.WriteLine($"产物索引 / Artifact index: {Safe(artifactIndexPath)} ({(File.Exists(artifactIndexPath) ? "已存在 / exists" : "未生成 / missing")})");
        Console.WriteLine($"事件 / Events: {FormatNullable(summary.ReportEventCount)} | 命中 / Findings: {FormatNullable(summary.FindingCount)} | 产物 / Artifacts: {FormatNullable(summary.ArtifactCount)} | 集合 / Collections: {FormatNullable(summary.CollectionCount)}");
        if (summary.MissingKeyArtifacts.Count > 0)
        {
            Console.WriteLine("缺失关键产物 / Missing key artifacts: " + Safe(string.Join(", ", summary.MissingKeyArtifacts)));
        }

        Console.WriteLine("下一步 / Next:");
        Console.WriteLine($"  重建报告 / Rebuild report: dotnet run --project tools/KSword.Sandbox.JobTool/KSword.Sandbox.JobTool.csproj -- rebuild-report --job-id {locator.JobId:D}");
        Console.WriteLine($"  检查产物 / Inspect artifacts: dotnet run --project tools/KSword.Sandbox.JobTool/KSword.Sandbox.JobTool.csproj -- inspect-artifacts --job-id {locator.JobId:D}");
        return 0;
    }

    private static int RebuildReport(JobToolOptions options, string commandName)
    {
        var initialContext = CreateContext(options);
        var locator = ResolveJobLocator(
            options,
            initialContext.Config,
            requireExisting: commandName.Equals("rebuild-report", StringComparison.OrdinalIgnoreCase));
        var runtimeRoot = ResolveServiceRuntimeRoot(options, initialContext.Config, locator);
        var context = CreateContext(options, runtimeRoot);
        EnsureServiceJobRootMatchesLocator(context.Config, locator);

        var samplePath = ResolveSamplePath(options, locator.JobRoot);
        var eventInput = ResolveEventInput(options, locator.JobRoot, locator.JobId, allowFailureSkeleton: true);
        var runbookExecutionPath = ResolveRunbookExecutionPath(options, locator.JobRoot);
        var duration = ParseNonNegativeInt(GetOption(options, "duration", GetOption(options, "duration-seconds", "120")), "duration");
        var displayName = GetOption(options, "display-name", Path.GetFileName(samplePath));
        var provider = ResolvePersistedOrConfiguredProvider(options, context.Config, locator.JobRoot);
        ValidateProviderResourceOverrides(options, context.Config, provider);
        var vmName = ResolvePersistedOrConfiguredVmName(options, context.Config, locator.JobRoot, provider);
        var snapshotName = ResolvePersistedOrConfiguredSnapshotName(options, context.Config, locator.JobRoot, provider);
        var machineDefinitionPath = ResolvePersistedOrConfiguredMachineDefinitionPath(options, context.Config, locator.JobRoot, provider);
        var qemuDiskFormat = ResolvePersistedOrConfiguredQemuDiskFormat(options, context.Config, locator.JobRoot, provider);
        var service = CreateService(context);
        AnalysisJob job;
        string reportRebuildDiagnosticsPath;
        try
        {
            job = service.ImportExternalRun(
                locator.JobId,
                new SandboxSubmission
                {
                    SamplePath = samplePath,
                    DisplayName = displayName,
                    DurationSeconds = duration,
                    DryRun = false,
                    Provider = provider,
                    GoldenVmName = vmName,
                    GoldenSnapshotName = snapshotName,
                    MachineDefinitionPath = machineDefinitionPath,
                    QemuDiskFormat = qemuDiskFormat
                },
                eventInput.Path,
                runbookExecutionPath);
            reportRebuildDiagnosticsPath = WriteReportRebuildDiagnostics(
                locator,
                commandName,
                samplePath,
                eventInput,
                runbookExecutionPath,
                success: true,
                message: "Report rebuilt without starting or mutating the VM.",
                rebuiltJob: job,
                provider: provider,
                vmName: vmName,
                baselineName: snapshotName,
                machineDefinitionPath: machineDefinitionPath,
                qemuDiskFormat: qemuDiskFormat);
        }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or DirectoryNotFoundException or InvalidOperationException or JsonException or IOException or UnauthorizedAccessException or KeyNotFoundException or FormatException)
        {
            reportRebuildDiagnosticsPath = WriteReportRebuildDiagnostics(
                locator,
                commandName,
                samplePath,
                eventInput,
                runbookExecutionPath,
                success: false,
                message: ex.Message,
                provider: provider,
                vmName: vmName,
                baselineName: snapshotName,
                machineDefinitionPath: machineDefinitionPath,
                qemuDiskFormat: qemuDiskFormat);
            throw new InvalidOperationException($"报告重建失败，诊断已写入 {reportRebuildDiagnosticsPath}。/ Report rebuild failed; diagnostics were written to {reportRebuildDiagnosticsPath}. {ex.Message}", ex);
        }

        var result = new
        {
            contractVersion = 1,
            kind = commandName.Equals("import-live", StringComparison.OrdinalIgnoreCase)
                ? "KSwordSandbox.ImportLiveResult"
                : "KSwordSandbox.ReportRebuildResult",
            command = commandName.Equals("import-live", StringComparison.OrdinalIgnoreCase) ? "import" : "report",
            status = job.Status.ToString(),
            jobId = job.JobId,
            jobRoot = locator.JobRoot,
            provider = job.Runbook?.Provider.ToString() ?? provider.ToString(),
            vmName = job.Runbook?.TargetVmName ?? vmName,
            baselineName = job.Runbook?.BaselineName ?? snapshotName,
            machineDefinitionPath = job.Runbook?.MachineDefinitionPath ?? machineDefinitionPath,
            qemuDiskFormat = job.Runbook?.QemuDiskFormat ?? qemuDiskFormat,
            samplePath,
            guestEventsPath = job.GuestEventsPath,
            runbookExecutionResultPath = job.RunbookExecutionResultPath,
            jsonReportPath = job.JsonReportPath,
            htmlReportPath = job.HtmlReportPath,
            htmlReportZhPath = job.HtmlReportZhPath,
            htmlReportEnPath = job.HtmlReportEnPath,
            artifactIndexPath = Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName),
            reportRebuildDiagnosticsPath,
            eventInput,
            messages = job.Messages,
            operatorMessage = eventInput.CreatedFailureSkeleton
                ? "报告已使用 failure skeleton 重建，未启动或修改 VM。/ Report rebuilt from a failure skeleton without starting or mutating the VM."
                : "报告已重建，未启动或修改 VM。/ Report rebuilt without starting or mutating the VM.",
            secretValuePrinted = false
        };

        if (commandName.Equals("import-live", StringComparison.OrdinalIgnoreCase) || GetBool(options, "json"))
        {
            WriteJson(result);
            return 0;
        }

        Console.WriteLine("报告重建 / KSword Sandbox report rebuild");
        Console.WriteLine($"任务 ID / Job ID: {job.JobId:D}");
        Console.WriteLine($"状态 / Status: {FormatStatusForHuman(job.Status.ToString())}");
        Console.WriteLine($"虚拟化后端 / Provider: {job.Runbook?.Provider.ToString() ?? provider.ToString()}");
        Console.WriteLine($"VM: {Safe(job.Runbook?.TargetVmName ?? vmName)}");
        Console.WriteLine($"干净基线 / Clean baseline: {Safe(job.Runbook?.BaselineName ?? snapshotName)}");
        if (!string.IsNullOrWhiteSpace(job.Runbook?.MachineDefinitionPath ?? machineDefinitionPath))
        {
            Console.WriteLine($"虚拟机定义 / Machine definition: {Safe(job.Runbook?.MachineDefinitionPath ?? machineDefinitionPath)}");
        }

        if (!string.IsNullOrWhiteSpace(job.Runbook?.QemuDiskFormat ?? qemuDiskFormat))
        {
            Console.WriteLine($"QEMU 磁盘格式 / Disk format: {Safe(job.Runbook?.QemuDiskFormat ?? qemuDiskFormat)}");
        }

        Console.WriteLine("VM 操作 / VM action: 无 / none");
        Console.WriteLine($"事件源 / Events: {Safe(job.GuestEventsPath ?? eventInput.Path)}");
        if (eventInput.CreatedFailureSkeleton)
        {
            Console.WriteLine("事件诊断 / Event diagnostic: 已生成 failure skeleton；仅用于失败报告，不代表 Guest Agent 完整运行。/ Generated failure skeleton for diagnostics only.");
        }

        Console.WriteLine($"JSON 报告 / Report JSON: {FormatPathForHuman(job.JsonReportPath)}");
        Console.WriteLine($"HTML 报告 / Report HTML: {FormatPathForHuman(job.HtmlReportPath)}");
        Console.WriteLine($"产物索引 / Artifact index: {Safe(Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName))}");
        Console.WriteLine($"重建诊断 / Rebuild diagnostics: {Safe(reportRebuildDiagnosticsPath)}");
        Console.WriteLine("完成 / Done: 已仅基于现有文件重新生成报告产物。/ Report artifacts were regenerated from existing files only.");
        return 0;
    }

    private static int InspectArtifacts(JobToolOptions options)
    {
        var context = CreateContext(options);
        var locator = ResolveJobLocator(options, context.Config, requireExisting: true);
        var builder = new HostArtifactIndexBuilder();
        var index = builder.Build(locator.JobId, locator.JobRoot);
        var writeIndex = GetBool(options, "write-index");
        ArtifactDescriptor? writtenDescriptor = null;
        if (writeIndex)
        {
            writtenDescriptor = builder.WriteIndex(locator.JobId, locator.JobRoot);
        }

        if (GetBool(options, "json"))
        {
            WriteJson(new
            {
                contractVersion = 1,
                kind = "KSwordSandbox.ArtifactInspection",
                command = "artifacts",
                jobId = locator.JobId,
                jobRoot = locator.JobRoot,
                wroteIndex = writeIndex,
                artifactIndexPath = Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName),
                writtenDescriptor,
                artifactCount = index.Artifacts.Count,
                collectionCount = index.Collections.Count,
                index,
                secretValuePrinted = false
            });
            return 0;
        }

        var limit = ParseLimit(options, defaultValue: 50);
        var includeMetadata = GetBool(options, "include-metadata");
        Console.WriteLine("产物检查 / KSword Sandbox artifact inspection");
        Console.WriteLine($"任务 ID / Job ID: {locator.JobId:D}");
        Console.WriteLine($"任务目录 / Job root: {Safe(locator.JobRoot)}");
        Console.WriteLine($"产物数 / Artifacts: {index.Artifacts.Count} | 集合数 / Collections: {index.Collections.Count}");
        Console.WriteLine($"已写索引 / Persisted index: {(writeIndex ? "是 / yes" : "否 / no")} {Safe(Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName))}");

        if (index.Collections.Count > 0)
        {
            Console.WriteLine("集合 / Collections:");
            foreach (var collection in index.Collections.OrderBy(collection => collection.Name, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine($"- {Safe(collection.Name)} | {FormatArtifactKindForHuman(collection.Kind)} | {FormatCollectionStatusForHuman(collection.Status)} | {Safe(collection.RelativePath)}");
                if (includeMetadata && collection.Metadata.Count > 0)
                {
                    WriteMetadata(collection.Metadata, indent: "  ");
                }
            }
        }

        if (index.Artifacts.Count == 0)
        {
            Console.WriteLine("未发现可索引产物。/ No indexed artifacts found.");
            return 0;
        }

        Console.WriteLine($"产物 / Artifacts（显示前 {Math.Min(limit, index.Artifacts.Count)} 个 / showing first {Math.Min(limit, index.Artifacts.Count)}）:");
        foreach (var artifact in index.Artifacts.Take(limit))
        {
            Console.WriteLine($"- {FormatArtifactKindForHuman(artifact.Kind)} | {FormatBytes(artifact.SizeBytes)} | {Safe(artifact.RelativePath)}");
            Console.WriteLine($"  SHA-256: {FormatValueOrUnavailable(artifact.Sha256)} | MIME: {FormatValueOrUnavailable(artifact.MimeType)}");
            Console.WriteLine($"  集合 / Collection: {FormatValueOrUnavailable(artifact.CollectionName)} | 状态 / Capture: {FormatValueOrUnavailable(artifact.CaptureState)} | 源事件 / Source event: {FormatValueOrUnavailable(ReadArtifactMetadata(artifact, "sourceEventType"))}");
            Console.WriteLine($"  下载 selector / Download selector: {Safe(FirstNonEmpty(artifact.SafeLink, artifact.RelativePath, artifact.ImportPath))}");
            if (includeMetadata && artifact.Metadata.Count > 0)
            {
                WriteMetadata(artifact.Metadata, indent: "  ");
            }
        }

        if (index.Artifacts.Count > limit)
        {
            Console.WriteLine($"... 还有 {index.Artifacts.Count - limit} 个 / {index.Artifacts.Count - limit} more。使用 --limit 或 --json 查看更多。/ Use --limit or --json for more.");
        }

        return 0;
    }
}

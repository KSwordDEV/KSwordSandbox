using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the shipped example configuration against machine-local paths.
///
/// config/sandbox.example.json is the only config file that travels with the
/// package (sandbox.local.json is gitignored). It used to hardcode the
/// authoring machine's D:\Temp\KSwordSandbox, so an operator who copied the
/// example silently pointed every job, report, and pcap at a drive they may not
/// have. It now leaves runtimeRoot empty, which means the loader must resolve a
/// portable location instead of the repository root - resolving to the source
/// tree would put jobs and reports inside git.
///
/// The PowerShell side of the same contract lives in
/// packaging.portable-path-defaults.contract.
/// </summary>
internal sealed class PortableConfigRootContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "config.portable-runtime-root.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var repositoryRoot = ResolveRepositoryRoot();
        SmokeAssert.True(repositoryRoot is not null, "The scenario must run inside a KSwordSandbox checkout.");

        // 1. The shipped example must not name a drive.
        var examplePath = Path.Combine(repositoryRoot!, "config", "sandbox.example.json");
        SmokeAssert.True(File.Exists(examplePath), "config/sandbox.example.json must ship with the package.");
        using (var document = JsonDocument.Parse(File.ReadAllText(examplePath)))
        {
            var paths = document.RootElement.GetProperty("paths");
            var runtimeRoot = paths.GetProperty("runtimeRoot").GetString() ?? string.Empty;
            var guestPayloadRoot = paths.GetProperty("guestPayloadRoot").GetString() ?? string.Empty;
            SmokeAssert.True(runtimeRoot.Length == 0,
                $"sandbox.example.json must leave paths.runtimeRoot empty so the loader resolves a portable location; found '{runtimeRoot}'.");
            SmokeAssert.True(guestPayloadRoot.Length == 0,
                $"sandbox.example.json must leave paths.guestPayloadRoot empty; found '{guestPayloadRoot}'.");
            SmokeAssert.True(paths.TryGetProperty("_note", out _),
                "sandbox.example.json must document why the path fields are empty.");
        }

        // 2. Typed defaults must stay empty so the loader, not the record
        //    initializer, decides where evidence lands.
        var defaults = new SandboxPaths();
        SmokeAssert.True(defaults.RuntimeRoot.Length == 0,
            "SandboxPaths.RuntimeRoot must default to empty instead of the authoring machine's D:\\Temp\\KSwordSandbox.");
        SmokeAssert.True(defaults.GuestPayloadRoot.Length == 0,
            "SandboxPaths.GuestPayloadRoot must default to empty.");

        // 3. An empty root must resolve outside the repository and outside the
        //    source tree. This is the behavior that protects a fresh operator.
        var resolved = SandboxConfigLoader.Load(null, repositoryRoot!);
        SmokeAssert.True(!string.IsNullOrWhiteSpace(resolved.Paths.RuntimeRoot),
            "An omitted config must still resolve a runtime root.");
        SmokeAssert.True(!IsUnder(resolved.Paths.RuntimeRoot!, repositoryRoot!),
            $"An empty runtimeRoot must not resolve inside the repository; got '{resolved.Paths.RuntimeRoot}'.");
        SmokeAssert.True(!IsUnder(resolved.Paths.GuestPayloadRoot!, repositoryRoot!),
            $"The derived guest payload root must not resolve inside the repository; got '{resolved.Paths.GuestPayloadRoot}'.");
        SmokeAssert.True(Path.IsPathRooted(resolved.Paths.RuntimeRoot!),
            "The resolved runtime root must be absolute.");

        // 4. An explicit configured path still wins, including when it points at
        //    a drive the current machine lacks.
        var explicitRoot = Path.Combine(Path.GetTempPath(), "ksword-portable-root-probe");
        var explicitConfig = new SandboxConfig();
        var withExplicit = explicitConfig with
        {
            Paths = explicitConfig.Paths with { RuntimeRoot = explicitRoot }
        };
        var explicitResolved = Resolve(withExplicit, repositoryRoot!);
        SmokeAssert.True(string.Equals(explicitResolved.Paths.RuntimeRoot, Path.GetFullPath(explicitRoot), StringComparison.OrdinalIgnoreCase),
            $"An explicit runtimeRoot must win over the portable default; got '{explicitResolved.Paths.RuntimeRoot}'.");

        // 5. rulesDirectory keeps resolving against the repository root; only
        //    evidence roots move out of the source tree.
        SmokeAssert.True(IsUnder(resolved.Paths.RulesDirectory!, repositoryRoot!),
            "rulesDirectory must stay repository-relative so the shipped rules are found.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Shipped configuration and typed defaults resolve a portable runtime root instead of the authoring machine's D: drive."
        });
    }

    private static SandboxConfig Resolve(SandboxConfig config, string repositoryRoot)
    {
        var json = JsonSerializer.Serialize(config);
        var path = Path.Combine(Path.GetTempPath(), $"ksword-portable-config-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        try
        {
            return SandboxConfigLoader.Load(path, repositoryRoot);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string? ResolveRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "KSwordSandbox.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return null;
    }

    private static bool IsUnder(string candidate, string root)
    {
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(candidate).StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase);
    }
}
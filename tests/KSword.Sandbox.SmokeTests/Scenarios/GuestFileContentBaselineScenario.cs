using System.Security.Cryptography;
using KSword.Sandbox.Agent.Collection;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Exercises a bounded user-content before-image with harmless local files.
/// A pure bulk rename must retain identical content, while rename followed by
/// changed bytes carries comparable size/hash evidence for generic rules.
/// </summary>
internal sealed class GuestFileContentBaselineScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest.file-content-baseline.contract";

    public async Task<SmokeTestResult> RunAsync(
        SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var root = Path.Combine(context.RuntimeRoot, "content-baseline-" + Guid.NewGuid().ToString("N"));
        var content = Path.Combine(root, "Documents");
        var work = Path.Combine(root, "work");
        Directory.CreateDirectory(content);
        Directory.CreateDirectory(work);
        var originals = Enumerable.Range(1, 6)
            .Select(index => Path.Combine(content, $"ordinary-{index:000}.{(index % 2 == 0 ? "docx" : "txt")}"))
            .ToArray();
        var before = Enumerable.Range(1, 6)
            .Select(index => Enumerable.Repeat((byte)index, 4096).ToArray())
            .ToArray();
        for (var index = 0; index < originals.Length; index++)
        {
            await File.WriteAllBytesAsync(originals[index], before[index], cancellationToken).ConfigureAwait(false);
        }
        await File.WriteAllBytesAsync(Path.Combine(content, "large-unhashed.bin"),
            new byte[1024 * 1024 + 1], cancellationToken).ConfigureAwait(false);

        var probe = new FileDiffProbe(new FileSnapshotProvider(), [content]);
        var probeContext = new GuestProbeContext
        {
            SamplePath = Path.Combine(work, "synthetic-sample.exe"),
            WorkingDirectory = work,
            OutputDirectory = work,
            RootProcessId = 1234,
            RootParentProcessId = 1,
            RootProcessName = "synthetic",
            RootProcessPath = Path.Combine(work, "synthetic-sample.exe"),
            RootCommandLine = "synthetic"
        };

        try
        {
            var setup = await probe.CollectAsync(ProbePhase.BeforeStart, probeContext, cancellationToken)
                .ConfigureAwait(false);
            var summary = setup.Single(evt => evt.EventType == "file.content_baseline.summary");
            SmokeAssert.True(summary.Data.GetValueOrDefault("fileCount") == "7" &&
                             summary.Data.GetValueOrDefault("hashedFileCount") == "6" &&
                             summary.Data.GetValueOrDefault("skippedHashCount") == "1" &&
                             summary.Data.GetValueOrDefault("captureState") == "partial" &&
                             summary.Data.GetValueOrDefault("truncated") == "false" &&
                             summary.Data.GetValueOrDefault("nonbehavior") == "true",
                "BeforeStart must hash six small files, disclose one oversized file, and mark the summary nonbehavior.");

            var destinations = originals.Select(path => path + ".moved").ToArray();
            for (var index = 0; index < originals.Length; index++)
            {
                File.Move(originals[index], destinations[index]);
                if (index < 5)
                {
                    await File.AppendAllTextAsync(destinations[index], "changed", cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            await Task.Delay(350, cancellationToken).ConfigureAwait(false);
            var during = await probe.CollectAsync(ProbePhase.DuringRun, probeContext, cancellationToken)
                .ConfigureAwait(false);
            var renames = during.Where(evt => evt.EventType == "file.renamed" &&
                                               evt.Data.GetValueOrDefault("oldPath") is not null &&
                                               evt.Data.GetValueOrDefault("contentBaselineStatus") == "captured")
                .GroupBy(evt => evt.Data["oldPath"], StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToDictionary(evt => evt.Data["oldPath"], StringComparer.OrdinalIgnoreCase);
            SmokeAssert.True(renames.Count == 6,
                $"Watcher must retain six independent rename edges; got {renames.Count}: " +
                string.Join(", ", during.Where(evt => evt.EventType == "file.renamed")
                    .Select(evt => evt.Data.GetValueOrDefault("oldPath") ?? evt.Path)));

            for (var index = 0; index < originals.Length; index++)
            {
                var row = renames[originals[index]];
                var expectedHash = Convert.ToHexString(SHA256.HashData(before[index])).ToLowerInvariant();
                SmokeAssert.True(row.Data.GetValueOrDefault("previousSha256") == expectedHash &&
                                 row.Data.GetValueOrDefault("previousSizeBytes") == "4096" &&
                                 row.Data.GetValueOrDefault("baselineHashStatus") == "computed" &&
                                 row.Data.GetValueOrDefault("previousPathAbsentAtDrain") == "true",
                    "Rename must carry the bounded original hash, size, and disappearance evidence.");
                SmokeAssert.True(row.Data.GetValueOrDefault("contentChangedFromBaseline") ==
                                 (index < 5 ? "true" : "false"),
                    "A pure bulk rename must not claim changed bytes; rewritten files must.");
            }

            await probe.CollectAsync(ProbePhase.AfterRun, probeContext, cancellationToken)
                .ConfigureAwait(false);
            return new SmokeTestResult
            {
                ScenarioId = ScenarioId,
                Passed = true,
                Message = "Bounded user baseline proved five content changes and rejected one pure rename."
            };
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}

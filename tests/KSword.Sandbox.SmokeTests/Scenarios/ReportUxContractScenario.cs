using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the HTML report renderer and UX documentation expose the
/// operator-facing sections needed for a live sandbox demo. Inputs are source
/// and docs files; processing performs static contract checks; the scenario
/// returns pass/fail metadata.
/// </summary>
internal sealed class ReportUxContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.ux.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rendererPath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Reporting", "HtmlReportRenderer.cs");
        var reportStagePath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Pipeline", "Stages", "ReportArtifactStage.cs");
        var analysisModelsPath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Abstractions", "AnalysisModels.cs");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "report-ux.md");

        SmokeAssert.True(File.Exists(rendererPath), "HTML report renderer is missing.");
        SmokeAssert.True(File.Exists(reportStagePath), "Report artifact stage is missing.");
        SmokeAssert.True(File.Exists(analysisModelsPath), "Analysis job model is missing.");
        SmokeAssert.True(File.Exists(docPath), "Report UX documentation is missing.");

        var rendererSource = File.ReadAllText(rendererPath);
        var reportStage = File.ReadAllText(reportStagePath);
        var analysisModels = File.ReadAllText(analysisModelsPath);
        var doc = File.ReadAllText(docPath);

        RequireContains(rendererSource, "AppendTimeline", "Report renderer should include a timeline section.");
        RequireContains(rendererSource, "AppendProcessTree", "Report renderer should include a process tree.");
        RequireContains(rendererSource, "AppendBehaviorGraph", "Report renderer should include a behavior graph and IOC summary section.");
        RequireContains(rendererSource, "Behavior graph / IOC summary", "Report renderer should expose a graph/IOC section title.");
        RequireContains(rendererSource, "Evidence graph edges", "Report renderer should expose graph edge evidence.");
        RequireContains(rendererSource, "IOC summary", "Report renderer should expose IOC summary cards.");
        RequireContains(rendererSource, "tls.", "Report renderer should classify TLS events as network behavior.");
        RequireContains(rendererSource, "pcap.", "Report renderer should classify PCAP-derived events as network behavior.");
        RequireContains(rendererSource, "AppendRegistryBehavior", "Report renderer should include registry behavior.");
        RequireContains(rendererSource, "data-copy", "Report renderer should expose copyable evidence fields.");
        RequireContains(rendererSource, "contextmenu", "Report renderer should support right-click copy.");
        RequireContains(rendererSource, "Copy event", "Report renderer should provide explicit copy buttons.");
        RequireContains(rendererSource, "Raw normalized events", "Report renderer should include raw event evidence.");
        RequireContains(rendererSource, "RawEventInlineLimit = 200", "Report renderer should cap inline raw event rendering.");
        RequireContains(rendererSource, "raw-events-shell", "Report renderer should collapse raw events with native HTML.");
        RequireContains(rendererSource, "raw-events-panel", "Report renderer should bound expanded raw event height.");
        RequireContains(rendererSource, "Hidden raw events", "Report renderer should expose hidden raw event counts.");
        RequireContains(rendererSource, "report.json", "Report renderer should point operators to report.json.");
        RequireContains(rendererSource, "raw source artifacts", "Report renderer should point operators to raw source artifacts.");
        RequireContains(rendererSource, "#43A0FF", "Report renderer should use the required primary accent color.");
        RequireAnyContains(
            rendererSource,
            ["modern sandbox report", "modern-sandbox-report", "report-shell", "dashboard"],
            "Report renderer should expose a modern sandbox report layout.");
        RequireContainsNormalized(rendererSource, "max-height:75vh", "Major report sections should be bounded to around 75vh.");
        RequireContainsNormalized(rendererSource, "overflow:auto", "Major report sections should scroll overflowing evidence.");
        RequireAnyContains(
            rendererSource,
            ["report.zh.html", "report.en.html", "RenderChinese", "RenderEnglish", "zh-CN", "en-US"],
            "Report renderer should support Chinese and English report rendering entrypoints.");
        RequireContains(rendererSource, "report.zh.html", "Report renderer should include the report.zh.html output clue.");
        RequireContains(rendererSource, "report.en.html", "Report renderer should include the report.en.html output clue.");
        RequireContains(rendererSource, "RenderBilingualReports", "Report renderer should provide a bilingual report generation entrypoint.");
        RequireContains(rendererSource, "AppendLanguageEntrypoints", "Report renderer should expose in-report bilingual navigation links.");
        RequireContains(rendererSource, "Report language", "Report renderer should label the bilingual report entry bar.");
        RequireContains(rendererSource, "id=\\\"cover\\\"", "Report renderer should expose a cover anchor.");
        RequireContains(rendererSource, "id=\\\"toc\\\"", "Report renderer should expose a table-of-contents anchor.");
        RequireContains(analysisModels, "HtmlReportZhPath", "Analysis job model should have a Chinese HTML report path for automatic report links.");
        RequireContains(analysisModels, "HtmlReportEnPath", "Analysis job model should have an English HTML report path for automatic report links.");
        RequireContains(reportStage, "report.artifacts.write", "Report stage should expose a stable progress stage id.");
        RequireContains(reportStage, "Write report artifacts", "Report stage should expose an operator-facing progress title.");
        RequireContains(reportStage, "report.html", "Report stage should keep writing the default report.html artifact.");

        RequireContains(doc, "Timeline", "Report UX doc should list the timeline section.");
        RequireContains(doc, "Behavior graph / IOC summary", "Report UX doc should list the behavior graph section.");
        RequireContains(doc, "Evidence graph edges", "Report UX doc should require graph edge evidence.");
        RequireContains(doc, "IOC summary", "Report UX doc should require IOC summary cards.");
        RequireContains(doc, "Process tree", "Report UX doc should list the process tree.");
        RequireContains(doc, "Registry behavior", "Report UX doc should list registry behavior.");
        RequireContains(doc, "Right-click", "Report UX doc should describe right-click copy.");
        RequireContains(doc, "raw events only", "Report UX doc should distinguish live raw events from final classification.");
        RequireContains(doc, "first 200 raw events", "Report UX doc should require a raw event inline limit.");
        RequireContains(doc, "hidden raw events", "Report UX doc should require hidden raw event counts.");
        RequireContains(doc, "report.json", "Report UX doc should require report.json source hints.");
        RequireContains(doc, "raw source artifact path hints", "Report UX doc should require raw source path hints.");
        RequireContains(doc, "native HTML/CSS", "Report UX doc should keep raw event expansion independent of JavaScript.");
        RequireContains(doc, "#43A0FF", "Report UX doc should specify the report primary accent color.");
        RequireContains(doc, "modern sandbox report layout", "Report UX doc should require the modern sandbox report layout.");
        RequireContains(doc, "75vh", "Report UX doc should specify bounded major report section height.");
        RequireContains(doc, "overflow:auto", "Report UX doc should specify scrolling major report sections.");
        RequireContains(doc, "Chinese and English", "Report UX doc should require Chinese and English report rendering support.");
        RequireContains(doc, "bilingual entry bar", "Report UX doc should require stable in-report bilingual entry links.");
        RequireContains(doc, "report.zh.html", "Report UX doc should mention report.zh.html.");
        RequireContains(doc, "report.en.html", "Report UX doc should mention report.en.html.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html?lang=zh", "Report UX doc should describe the Chinese served report endpoint validation.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html?lang=en", "Report UX doc should describe the English served report endpoint validation.");
        RequireContains(doc, "Cover / 封面", "Report UX doc should list the cover section.");
        RequireContains(doc, "Table of contents / 目录", "Report UX doc should list the table of contents section.");
        RequireContains(doc, "Behavior detections / 行为命中", "Report UX doc should list behavior hits.");
        RequireContains(doc, "R0 / driver events", "Report UX doc should list R0 driver events.");
        RequireContains(doc, "Raw normalized events / 原始事件", "Report UX doc should list raw events.");

        RequireRenderedReportContract();

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Report UX sections and copyable evidence contracts are present."
        });
    }

    /// <summary>
    /// Requires a text fragment to be present. Inputs are content, expected
    /// text, and failure message; processing throws on absence; return value is
    /// none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires one of several text fragments to be present. Inputs are content,
    /// expected alternatives, and failure message; processing throws on absence;
    /// return value is none.
    /// </summary>
    private static void RequireAnyContains(string content, IReadOnlyCollection<string> expectedAny, string message)
    {
        SmokeAssert.True(expectedAny.Any(expected => content.Contains(expected, StringComparison.Ordinal)), message);
    }

    /// <summary>
    /// Requires a CSS-like fragment to be present after whitespace removal.
    /// Inputs are content, expected normalized text, and failure message;
    /// processing throws on absence; return value is none.
    /// </summary>
    private static void RequireContainsNormalized(string content, string expected, string message)
    {
        var normalized = new string(content.Where(c => !char.IsWhiteSpace(c)).ToArray());
        SmokeAssert.True(normalized.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Renders synthetic English and Chinese reports to verify the UX contract
    /// against emitted HTML rather than source strings only. Inputs are none;
    /// processing builds a deterministic report model and checks required
    /// section anchors, bilingual filenames, accent color, bounded cards, and
    /// localized labels; the method returns no value on success.
    /// </summary>
    private static void RequireRenderedReportContract()
    {
        var report = BuildContractReport();
        var renderer = new HtmlReportRenderer();
        var englishHtml = renderer.RenderEnglish(report);
        var chineseHtml = renderer.RenderChinese(report);
        var documents = renderer.RenderBilingualReports(report);

        RequireContains(englishHtml, "#43A0FF", "Rendered HTML should include the required bright-blue accent color.");
        RequireContainsNormalized(englishHtml, "max-height:75vh", "Rendered major sections should be bounded to around 75vh.");
        RequireContainsNormalized(englishHtml, "overflow:auto", "Rendered major sections should scroll overflowing evidence.");
        RequireContains(englishHtml, "href=\"report.zh.html\"", "Rendered HTML should link to report.zh.html.");
        RequireContains(englishHtml, "href=\"report.en.html\"", "Rendered HTML should link to report.en.html.");
        RequireContains(englishHtml, "<details class=\"raw-events-shell\"><summary>Show inline raw events (200/211; 11 hidden)</summary>", "Rendered raw events should be collapsed and capped.");
        RequireContains(englishHtml, "Total events", "Rendered raw event overview should show the total count label.");
        RequireContains(englishHtml, "Hidden raw events", "Rendered raw event overview should show the hidden count label.");
        RequireContains(englishHtml, "Raw source paths", "Rendered raw event section should show source path hints.");
        RequireContains(englishHtml, "report.json", "Rendered raw event section should link or hint report.json.");
        RequireContains(englishHtml, "No raw source artifacts were indexed; report.json remains the complete normalized source.", "Rendered raw source hints should explain missing raw artifacts.");
        RequireContains(englishHtml, "<section id=\"graph\" class=\"card\"><h2>Behavior graph / IOC summary</h2>", "Rendered HTML should include the behavior graph section.");
        RequireContains(englishHtml, "Evidence graph edges", "Rendered HTML should include graph edge evidence.");
        RequireContains(englishHtml, "IOC summary", "Rendered HTML should include IOC summary cards.");
        RequireContains(englishHtml, "Network IOCs", "Rendered HTML should include network IOC cards.");

        foreach (var expected in RequiredEnglishSectionFragments())
        {
            RequireContains(englishHtml, expected, $"Rendered English report should include {expected}.");
        }

        RequireContains(chineseHtml, "<html lang=\"zh-CN\">", "Chinese HTML should set the zh-CN language metadata.");
        foreach (var expected in RequiredChineseSectionLabels())
        {
            RequireContains(chineseHtml, expected, $"Rendered Chinese report should include {expected}.");
        }

        SmokeAssert.True(
            documents.Any(document =>
                string.Equals(document.FileName, "report.en.html", StringComparison.OrdinalIgnoreCase) &&
                document.Language == HtmlReportLanguage.English &&
                string.Equals(document.CultureName, "en-US", StringComparison.Ordinal)),
            "Bilingual render output should include report.en.html with en-US metadata.");
        SmokeAssert.True(
            documents.Any(document =>
                string.Equals(document.FileName, "report.zh.html", StringComparison.OrdinalIgnoreCase) &&
                document.Language == HtmlReportLanguage.ChineseSimplified &&
                string.Equals(document.CultureName, "zh-CN", StringComparison.Ordinal)),
            "Bilingual render output should include report.zh.html with zh-CN metadata.");
    }

    /// <summary>
    /// Returns exact emitted English section fragments that represent the
    /// report's required major chapters. Inputs are none; processing returns
    /// stable substrings from rendered HTML; the caller checks each fragment.
    /// </summary>
    private static IReadOnlyList<string> RequiredEnglishSectionFragments() =>
    [
        "<header id=\"cover\">",
        "<nav id=\"toc\" class=\"card toc\"><h2>Table of contents</h2>",
        "<section id=\"risk\" class=\"card\"><h2>Risk summary</h2>",
        "<section id=\"behavior\" class=\"card\"><h2>Behavior detections</h2>",
        "<section id=\"mitre\" class=\"card\"><h2>Multi-dimensional / MITRE detections</h2>",
        "<section id=\"static\" class=\"card\"><h2>Static analysis</h2>",
        "<section id=\"dynamic\" class=\"card\"><h2>Dynamic analysis</h2>",
        "<section id=\"graph\" class=\"card\"><h2>Behavior graph / IOC summary</h2>",
        "<section id=\"process\" class=\"card\"><h2>Process details</h2>",
        "<section id=\"files\" class=\"card\"><h2>Dropped files</h2>",
        "<section id=\"registry\" class=\"card\"><h2>Registry behavior</h2>",
        "<section id=\"network\" class=\"card\"><h2>Network behavior</h2>",
        "<section id=\"r0\" class=\"card\"><h2>R0 / driver events</h2>",
        "<section id=\"failure\" class=\"card\"><h2>Failure reasons</h2>",
        "<section id=\"events\" class=\"card\"><h2>Raw normalized events</h2>"
    ];

    /// <summary>
    /// Returns localized labels required in the Chinese report. Inputs are
    /// none; processing returns stable shell labels that should appear after
    /// localization; the caller checks each label.
    /// </summary>
    private static IReadOnlyList<string> RequiredChineseSectionLabels() =>
    [
        "封面",
        "目录",
        "风险摘要",
        "行为命中",
        "多维 / MITRE 检测",
        "静态分析",
        "动态分析",
        "行为图谱 / IOC 摘要",
        "进程详情",
        "落地文件",
        "注册表行为",
        "网络行为",
        "R0 / 驱动事件",
        "失败原因",
        "原始事件"
    ];

    /// <summary>
    /// Builds a deterministic report with one event in every dynamic chapter.
    /// Inputs are none; processing creates synthetic sample, static, finding,
    /// process, file, registry, network, R0, and failure evidence; the method
    /// returns the report model for HTML rendering checks.
    /// </summary>
    private static AnalysisReport BuildContractReport()
    {
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var processEvent = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp,
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            ParentProcessId = 1000,
            Path = @"C:\Samples\contract-sample.exe",
            CommandLine = @"C:\Samples\contract-sample.exe --contract"
        };
        var fileEvent = new SandboxEvent
        {
            EventType = "file.created",
            Timestamp = timestamp.AddSeconds(1),
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Path = @"C:\Users\Public\drop.bin"
        };
        var registryEvent = new SandboxEvent
        {
            EventType = "registry.set",
            Timestamp = timestamp.AddSeconds(2),
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Contract"
        };
        var networkEvent = new SandboxEvent
        {
            EventType = "network.tcp",
            Timestamp = timestamp.AddSeconds(3),
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Data =
            {
                ["remoteAddress"] = "203.0.113.10",
                ["remotePort"] = "443"
            }
        };
        var r0Event = new SandboxEvent
        {
            EventType = "driver.file.create",
            Timestamp = timestamp.AddSeconds(4),
            Source = "driver",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Path = @"C:\Users\Public\r0-drop.bin",
            Data =
            {
                ["driverEventPath"] = "driver-events.jsonl"
            }
        };
        var failureEvent = new SandboxEvent
        {
            EventType = "analysis.timeout",
            Timestamp = timestamp.AddSeconds(5),
            Source = "host",
            Data =
            {
                ["reason"] = "contract timeout evidence"
            }
        };
        var events = new List<SandboxEvent> { processEvent, fileEvent, registryEvent, networkEvent, r0Event, failureEvent };
        for (var index = 0; index < 205; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = $"contract.raw.{index:D3}",
                Timestamp = timestamp.AddSeconds(10 + index),
                Source = "guest",
                ProcessName = "contract-sample.exe",
                ProcessId = 4242,
                Data =
                {
                    ["index"] = index.ToString(),
                    ["rawSource"] = "events.json"
                }
            });
        }

        return new AnalysisReport
        {
            JobId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
            GeneratedAt = timestamp,
            Status = AnalysisStatus.Failed,
            Sample = new SampleIdentity
            {
                FileName = "contract-sample.exe",
                FullPath = @"D:\Samples\contract-sample.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            StaticAnalysis = new StaticAnalysisResult
            {
                FileFormat = "PE32+",
                Magic = "MZ",
                IsPe = true,
                Architecture = "x64",
                Subsystem = "Windows GUI",
                EntryPointRva = "0x1000",
                SectionCount = 1,
                Sections =
                [
                    new PeSectionInfo
                    {
                        Name = ".text",
                        VirtualAddress = "0x1000",
                        VirtualSize = 4096,
                        RawDataSize = 2048,
                        Entropy = 6.2
                    }
                ],
                Tags = ["contract-tag"],
                Urls = ["https://example.invalid/contract"],
                InterestingStrings =
                [
                    "import:kernel32.dll!CreateFileW",
                    @"registry-path:HKCU\Software\Contract"
                ],
                Warnings = ["synthetic warning"]
            },
            Events = events,
            Findings =
            [
                new BehaviorFinding
                {
                    RuleId = "contract-behavior-hit",
                    Title = "Synthetic behavior hit",
                    Severity = "medium",
                    MitreTechniqueId = "T1059",
                    MitreTechniqueName = "Command and Scripting Interpreter",
                    Summary = "Synthetic behavior evidence for report UX contract.",
                    Evidence = [processEvent]
                }
            ],
            Metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["events.total"] = events.Count
            }
        };
    }
}

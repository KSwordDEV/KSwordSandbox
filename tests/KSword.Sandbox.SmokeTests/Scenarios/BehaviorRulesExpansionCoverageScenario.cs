using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the broader behavior-rule expansion over actual SandboxEvent fields
/// currently emitted by guest probes, R0/driver importers, and future protocol
/// post-processors.
/// </summary>
internal sealed class BehaviorRulesExpansionCoverageScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "screenshot-captured-artifact",
        "screenshot-capture-skipped",
        "memory-dump-captured-artifact",
        "memory-dump-capture-skipped",
        "dropped-file-artifact-copied",
        "dropped-file-artifact-skipped",
        "dropped-executable-artifact-copied",
        "artifact-manifest-written",
        "process-tree-observed",
        "process-tree-root-unavailable",
        "process-start-failed",
        "process-tree-child-count-observed",
        "lolbin-process-tree-node",
        "execution-from-user-writable-tree-path",
        "service-system-change-created",
        "service-system-change-suspicious-command",
        "scheduled-task-system-change-created",
        "scheduled-task-suspicious-target",
        "startup-item-system-change-created",
        "startup-item-executable-value",
        "persistence-system-item-deleted",
        "system-diff-truncated",
        "dns-cache-added",
        "dns-cache-txt-or-tunnel",
        "dns-cache-dynamic-domain",
        "netstat-connection-observed",
        "netstat-added-connection",
        "network-listener-opened",
        "network-nonstandard-listener-port",
        "network-connection-closed",
        "network-c2-indicator-fields",
        "dns-tunnel-or-dga-indicator",
        "pcap-artifact-imported",
        "pcap-protocol-summary-placeholder",
        "pcap-flow-observed",
        "pcap-http-request-observed",
        "pcap-dns-query-observed",
        "pcap-tls-clienthello-observed",
        "smb-network-port-observed",
        "winrm-network-port-observed",
        "http-executable-download",
        "http-post-or-checkin-beacon",
        "http-doh-request",
        "http-proxy-or-tunnel-method",
        "tls-invalid-certificate",
        "tls-encrypted-clienthello-or-esni",
        "pcap-executable-payload",
        "pcap-dns-nxdomain-or-dga",
        "pcap-upload-or-exfil-indicator",
        "pcap-flow-count-metadata-observed",
        "rdp-network-port-observed",
        "ssh-network-port-observed",
        "ldap-kerberos-network-port-observed",
        "tor-or-proxy-port-observed",
        "admin-share-file-path-observed",
        "remote-desktop-command-observed",
        "network-share-discovery-command",
        "system-discovery-command",
        "process-discovery-command",
        "network-discovery-command",
        "screenshot-api-observed",
        "file-masquerading-double-extension",
        "hidden-file-attribute-command"
    ];

    private static readonly IReadOnlyDictionary<string, string[]> PcapImporterDataKeyContract =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["pcap.summary"] = ["flowCount", "packetCount"],
            ["pcap.flow"] = ["sourceIp", "sourcePort", "destinationIp", "destinationPort", "protocol"],
            ["pcap.dns"] = ["sourceIp", "sourcePort", "destinationIp", "destinationPort", "protocol", "queryName", "rcode"],
            ["pcap.http"] = ["sourceIp", "sourcePort", "destinationIp", "destinationPort", "protocol", "host", "method", "uri", "contentType", "payloadMagic"],
            ["pcap.tls"] = ["sourceIp", "sourcePort", "destinationIp", "destinationPort", "protocol", "sni"]
        };

    public string ScenarioId => "behavior.rules-expansion-coverage-v2";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var ruleIds = rules.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        AssertPcapImporterDataKeyContract(rules);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(ruleIds.Contains(ruleId), $"Expanded behavior rule '{ruleId}' is missing.");
        }

        var engine = new RuleEngine(rules);
        var findings = engine.Classify(CreateSyntheticEvents());
        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic expanded behavior events should match '{ruleId}'.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"Expanded behavior coverage rules load and match {RequiredRuleIds.Length} representative synthetic rules."
        });
    }

    private static void AssertPcapImporterDataKeyContract(BehaviorRuleSet rules)
    {
        foreach (var (eventType, expectedKeys) in PcapImporterDataKeyContract)
        {
            var coveredKeys = rules.Rules
                .Where(rule => rule.EventTypes.Any(candidate => string.Equals(candidate, eventType, StringComparison.OrdinalIgnoreCase)))
                .SelectMany(rule => rule.DataKeys.Concat(rule.DataContains.Keys))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var expectedKey in expectedKeys)
            {
                SmokeAssert.True(
                    coveredKeys.Contains(expectedKey),
                    $"PCAP importer field '{eventType}.{expectedKey}' should be covered by a behavior rule data predicate.");
            }
        }
    }

    /// <summary>
    /// Builds compact synthetic coverage for artifact capture, dropped files,
    /// process trees, persistence diffs, DNS/HTTP/TLS/PCAP evidence, discovery,
    /// lateral movement, screen capture, and file hiding.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateSyntheticEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "screenshot.captured",
                Source = "guest",
                Path = @"C:\KSwordSandbox\out\screenshots\after-run.bmp",
                Data =
                {
                    ["phase"] = "after-run",
                    ["widthPixels"] = "1024",
                    ["heightPixels"] = "768",
                    ["relativePath"] = "screenshots/after-run.bmp"
                }
            },
            new SandboxEvent
            {
                EventType = "screenshot.skipped",
                Source = "guest",
                Data =
                {
                    ["reason"] = "No visible desktop surface is available.",
                    ["diagnosticStage"] = "capture"
                }
            },
            new SandboxEvent
            {
                EventType = "memory_dump.captured",
                Source = "guest",
                Path = @"C:\KSwordSandbox\out\memory-dumps\sample.dmp",
                ProcessId = 4242,
                Data =
                {
                    ["evidenceRole"] = "memory-dump",
                    ["dumpType"] = "MiniDumpNormal",
                    ["sizeBytes"] = "4096"
                }
            },
            new SandboxEvent
            {
                EventType = "memory_dump.skipped",
                Source = "guest",
                Data =
                {
                    ["reason"] = "Sample root process ID is not available.",
                    ["diagnosticStage"] = "root-process"
                }
            },
            new SandboxEvent
            {
                EventType = "artifact.dropped_file.copied",
                Source = "guest",
                Path = @"C:\KSwordSandbox\out\artifacts\dropped-files\payload.exe",
                Data =
                {
                    ["evidenceRole"] = "dropped-file",
                    ["collectDroppedFiles"] = "true",
                    ["sourcePath"] = @"C:\Users\Public\payload.exe",
                    ["artifactRelativePath"] = "artifacts/dropped-files/payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "artifact.dropped_file.skipped",
                Source = "guest",
                Path = @"C:\Users\Public\missing.bin",
                Data =
                {
                    ["reason"] = "sourceFileMissing",
                    ["sourceEventType"] = "file.created",
                    ["sourcePath"] = @"C:\Users\Public\missing.bin",
                    ["collectDroppedFiles"] = "true"
                }
            },
            new SandboxEvent
            {
                EventType = "artifact.manifest.written",
                Source = "guest",
                Path = @"C:\KSwordSandbox\out\artifacts\manifest.json",
                Data =
                {
                    ["artifactCount"] = "3",
                    ["copiedDroppedFileCount"] = "1",
                    ["relativePath"] = "artifacts/manifest.json",
                    ["artifactRoot"] = @"C:\KSwordSandbox\out\artifacts"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                ProcessId = 5000,
                ParentProcessId = 4242,
                Path = @"C:\Windows\System32\rundll32.exe",
                Data =
                {
                    ["rootProcessId"] = "4242",
                    ["treeDepth"] = "1",
                    ["childProcessCount"] = "9",
                    ["treeLineage"] = "4242>5000",
                    ["parentProcessId"] = "4242"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                ProcessId = 5001,
                Path = @"C:\Users\Public\payload.exe",
                Data =
                {
                    ["rootProcessId"] = "4242",
                    ["treeDepth"] = "2"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree_unavailable",
                Source = "guest",
                ProcessId = 4242,
                Data =
                {
                    ["rootProcessId"] = "4242",
                    ["reason"] = "Root process was not visible.",
                    ["phase"] = "after-run"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start_failed",
                Source = "guest",
                Data =
                {
                    ["exceptionType"] = "System.ComponentModel.Win32Exception",
                    ["message"] = "The system cannot find the file specified."
                }
            },
            new SandboxEvent
            {
                EventType = "service.created",
                Source = "guest",
                Data =
                {
                    ["serviceName"] = "KswordSmokeSvc",
                    ["displayName"] = "KSword Smoke Service",
                    ["rawSummary"] = @"BINARY_PATH_NAME: C:\Users\Public\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "scheduled_task.created",
                Source = "guest",
                Path = @"\KswordSmoke",
                Data =
                {
                    ["taskName"] = @"\KswordSmoke",
                    ["taskToRun"] = @"powershell -ExecutionPolicy Bypass -File C:\Users\Public\payload.ps1",
                    ["rawSummary"] = "powershell payload",
                    ["author"] = "Smoke"
                }
            },
            new SandboxEvent
            {
                EventType = "startup_item.created",
                Source = "guest",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                Data =
                {
                    ["kind"] = "registry",
                    ["location"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    ["name"] = "KswordSmoke",
                    ["value"] = @"C:\Users\Public\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "scheduled_task.deleted",
                Source = "guest",
                Data =
                {
                    ["change"] = "deleted",
                    ["taskName"] = @"\OldTask"
                }
            },
            new SandboxEvent
            {
                EventType = "service.diff_truncated",
                Source = "guest",
                Data =
                {
                    ["totalCount"] = "400",
                    ["emittedCount"] = "256",
                    ["change"] = "created",
                    ["phase"] = "after-run"
                }
            },
            new SandboxEvent
            {
                EventType = "dns.cache.added",
                Source = "guest",
                Data =
                {
                    ["name"] = "tunnel.smoke.duckdns.org",
                    ["recordType"] = "TXT",
                    ["data"] = "chunk",
                    ["timeToLive"] = "30",
                    ["rawSummary"] = "TXT tunnel duckdns"
                }
            },
            new SandboxEvent
            {
                EventType = "network.netstat",
                Source = "guest",
                Data =
                {
                    ["protocol"] = "TCP",
                    ["local"] = "10.0.0.4:50000",
                    ["remote"] = "198.51.100.10:443",
                    ["state"] = "ESTABLISHED",
                    ["owningProcessId"] = "4242"
                }
            },
            new SandboxEvent
            {
                EventType = "network.netstat.added",
                Source = "guest",
                Data =
                {
                    ["protocol"] = "TCP",
                    ["remote"] = "10.0.0.10:3389",
                    ["state"] = "ESTABLISHED",
                    ["owningProcessId"] = "4242"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tcp.listener.opened",
                Source = "guest",
                Data =
                {
                    ["protocol"] = "TCP",
                    ["local"] = "127.0.0.1:9050",
                    ["localAddress"] = "127.0.0.1",
                    ["localPort"] = "9050",
                    ["state"] = "LISTENING"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tcp.closed",
                Source = "guest",
                Data =
                {
                    ["connection"] = "10.0.0.4:50000-198.51.100.10:443",
                    ["remote"] = "198.51.100.10:443",
                    ["remoteAddress"] = "198.51.100.10",
                    ["remotePort"] = "443",
                    ["state"] = "closed"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["url"] = "https://cloudflare-dns.com/dns-query/payload.exe",
                    ["requestUri"] = "/dns-query/payload.exe",
                    ["host"] = "cloudflare-dns.com",
                    ["method"] = "POST",
                    ["contentType"] = "application/dns-message",
                    ["headers"] = "Upgrade: websocket",
                    ["behavior"] = "beacon checkin c2 proxy tunnel"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["certValidation"] = "self-signed invalid",
                    ["extension"] = "encrypted_client_hello",
                    ["sni"] = "<encrypted>"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.flow",
                Source = "host",
                Data =
                {
                    ["sourceIp"] = "10.0.0.4",
                    ["sourcePort"] = "445",
                    ["destinationIp"] = "198.51.100.20",
                    ["destinationPort"] = "5985",
                    ["protocol"] = "tcp"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["sourceIp"] = "10.0.0.4",
                    ["sourcePort"] = "51516",
                    ["destinationIp"] = "198.51.100.21",
                    ["destinationPort"] = "443",
                    ["protocol"] = "http",
                    ["host"] = "download.example",
                    ["method"] = "POST",
                    ["uri"] = "/api/checkin/payload.exe",
                    ["payloadMagic"] = "MZ",
                    ["filename"] = "payload.exe",
                    ["contentType"] = "application/x-msdownload",
                    ["direction"] = "upload"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["sourceIp"] = "10.0.0.4",
                    ["sourcePort"] = "51517",
                    ["destinationIp"] = "198.51.100.53",
                    ["destinationPort"] = "53",
                    ["protocol"] = "dns",
                    ["queryName"] = "entropy-high.smoke.example",
                    ["rcode"] = "NXDOMAIN",
                    ["classification"] = "dga"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.tls",
                Source = "host",
                Data =
                {
                    ["sourceIp"] = "10.0.0.4",
                    ["sourcePort"] = "51518",
                    ["destinationIp"] = "198.51.100.22",
                    ["destinationPort"] = "443",
                    ["protocol"] = "tls",
                    ["sni"] = "c2.smoke.example"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.summary",
                Source = "host",
                Data =
                {
                    ["flowCount"] = "512",
                    ["packetCount"] = "4096",
                    ["uniqueDestinationCount"] = "120"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.protocol.summary",
                Source = "host",
                Data =
                {
                    ["protocol"] = "tls"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["remoteAddress"] = "203.0.113.22",
                    ["remotePort"] = "22"
                }
            },
            new SandboxEvent
            {
                EventType = "network.udp",
                Source = "guest",
                Data =
                {
                    ["remoteAddress"] = "10.0.0.5",
                    ["remotePort"] = "88"
                }
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = @"\TARGET\ADMIN$\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "mstsc.exe /v:TARGET"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"net view \TARGET"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "whoami /all"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "tasklist /v"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "ipconfig /all"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "BitBlt"
                }
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = @"C:\Users\Public\invoice.pdf.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"attrib +h C:\Users\Public\payload.exe"
            }
        ];
    }
}

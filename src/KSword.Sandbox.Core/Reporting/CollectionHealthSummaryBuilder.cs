using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting;

/// <summary>
/// Builds one collection-health view shared by live regeneration and
/// standalone post-processing. Inputs are raw/report normalized events;
/// processing recognizes explicit loss counters and known capture failures;
/// the returned model remains separate from sample behavior findings.
/// </summary>
public static class CollectionHealthSummaryBuilder
{
    private static readonly string[] EtwLostKeys =
    [
        "EventsLost",
        "eventsLost",
        "lostEvents"
    ];

    private static readonly string[] DriverLostKeys =
    [
        "lostCount",
        "eventsDropped",
        "TotalEventsDropped",
        "totalEventsDropped",
        "TotalEventsLost",
        "totalEventsLost",
        "rawJsonlLostEventCount",
        "rawJsonlLossRowCount"
    ];

    private static readonly string[] DriverQueueDepthKeys =
    [
        "queueDepth",
        "queueUnread",
        "unreadQueue",
        "eventsQueued"
    ];

    private static readonly string[] DriverRemainingUnreadKeys =
    [
        "remainingUnread",
        "remainingUnreadEvents",
        "remainingQueueDepth",
        "unread",
        "remaining",
        "remainingEvents"
    ];

    private static readonly string[] DriverSuppressedKeys =
    [
        "eventsSuppressed",
        "totalEventsSuppressed",
        "collectorSuppressedEvents",
        "selfNoiseSuppressedEvents",
        "suppressed"
    ];

    public static CollectionHealthSummary Build(
        IReadOnlyCollection<SandboxEvent> rawEvents,
        IReadOnlyCollection<SandboxEvent>? reportEvents = null)
    {
        reportEvents ??= rawEvents;
        var raw = rawEvents.Where(IsHealthRow).ToList();
        var report = reportEvents.Where(IsHealthRow).ToList();
        var etwLossRows = raw.Where(IsEtwLossRow).ToList();
        var driverLossRows = raw.Where(IsDriverLossRow).ToList();
        var driverHealthRows = raw.Where(IsDriverHealthRow).ToList();
        var failureRows = raw.Where(IsFailureRow).ToList();
        var omitted = Math.Max(0, raw.Count - report.Count);
        var driverQueueDepth = MaxDataUnsigned(driverHealthRows, DriverQueueDepthKeys);
        var driverRemainingUnread = MaxDataUnsigned(driverHealthRows, DriverRemainingUnreadKeys);
        // Older collector status contracts expose the unread tail only as
        // queueDepth. Preserve that value in the explicit remaining-unread
        // field so a non-zero queue cannot be mistaken for a complete drain.
        if (driverRemainingUnread == 0)
        {
            driverRemainingUnread = driverQueueDepth;
        }

        return new CollectionHealthSummary
        {
            RawRows = raw.Count,
            ReportRows = report.Count,
            OmittedRows = omitted,
            TotalRows = raw.Count,
            FailureRows = failureRows.Count,
            LossRows = raw.Count(IsLossRow),
            EtwEventsLostRows = etwLossRows.Count,
            EtwEventsLost = ToMetricInt(MaxDataUnsigned(etwLossRows, EtwLostKeys)),
            DriverLossRows = driverLossRows.Count,
            DriverLostCount = ToMetricInt(MaxDataUnsigned(driverLossRows, DriverLostKeys)),
            DriverQueueDepth = ToMetricInt(driverQueueDepth),
            DriverRemainingUnread = ToMetricInt(driverRemainingUnread),
            DriverDrainStoppedAtDeadlineRows = driverHealthRows.Count(IsDrainStoppedAtDeadline),
            DriverEventsSuppressed = ToMetricInt(MaxDataUnsigned(driverHealthRows, DriverSuppressedKeys)),
            DriverQualityWarningRows = driverHealthRows.Count(IsDriverQualityWarning),
            ProcessTreeUnavailable = raw.Count(IsProcessTreeUnavailable),
            ScheduledTaskCaptureFailed = raw.Count(IsScheduledTaskCaptureFailed),
            PktmonStopFailed = raw.Count(IsPktmonStopFailed),
            EtwDecodeFailed = raw.Count(IsEtwDecodeFailure)
        };
    }

    /// <summary>
    /// Adds stable aliases to the report metric dictionary so older consumers
    /// can read integer metrics while newer consumers use CollectionHealth.
    /// </summary>
    public static void AddMetrics(
        IDictionary<string, int> metrics,
        CollectionHealthSummary summary)
    {
        metrics["collectionHealth.raw"] = summary.RawRows;
        metrics["collectionHealth.report"] = summary.ReportRows;
        metrics["collectionHealth.omitted"] = summary.OmittedRows;
        metrics["collectionHealth.total"] = summary.TotalRows;
        metrics["collectionHealth.failures"] = summary.FailureRows;
        metrics["collectionHealth.losses"] = summary.LossRows;
        metrics["collectionHealth.etw.eventsLostRows"] = summary.EtwEventsLostRows;
        metrics["collectionHealth.etw.eventsLost"] = summary.EtwEventsLost;
        metrics["collectionHealth.driver.lossRows"] = summary.DriverLossRows;
        metrics["collectionHealth.driver.lostCount"] = summary.DriverLostCount;
        metrics["collectionHealth.driver.queueDepth"] = summary.DriverQueueDepth;
        metrics["collectionHealth.driver.remainingUnread"] = summary.DriverRemainingUnread;
        metrics["collectionHealth.driver.drainStoppedAtDeadlineRows"] = summary.DriverDrainStoppedAtDeadlineRows;
        metrics["collectionHealth.driver.eventsSuppressed"] = summary.DriverEventsSuppressed;
        metrics["collectionHealth.driver.qualityWarningRows"] = summary.DriverQualityWarningRows;
        metrics["collectionHealth.process.treeUnavailable"] = summary.ProcessTreeUnavailable;
        metrics["collectionHealth.scheduledTask.captureFailed"] = summary.ScheduledTaskCaptureFailed;
        metrics["collectionHealth.pktmon.stopFailed"] = summary.PktmonStopFailed;
        metrics["collectionHealth.etw.decodeFailed"] = summary.EtwDecodeFailed;
        metrics["runtime.collectionFailures"] = summary.FailureRows;
        metrics["runtime.failures"] = summary.FailureRows;
        metrics["events.runtime.collectionFailures"] = summary.FailureRows;
        metrics["events.runtime.failures"] = summary.FailureRows;

        // Metrics historically use an events.* namespace. Keep equivalent
        // aliases so report consumers can migrate from the flat health keys
        // without reparsing the raw diagnostic events.
        metrics["events.collectionHealth.raw"] = summary.RawRows;
        metrics["events.collectionHealth.report"] = summary.ReportRows;
        metrics["events.collectionHealth.omitted"] = summary.OmittedRows;
        metrics["events.collectionHealth.total"] = summary.TotalRows;
        metrics["events.collectionHealth.failures"] = summary.FailureRows;
        metrics["events.collectionHealth.losses"] = summary.LossRows;
        metrics["events.collectionHealth.etw.eventsLostRows"] = summary.EtwEventsLostRows;
        metrics["events.collectionHealth.etw.eventsLost"] = summary.EtwEventsLost;
        metrics["events.collectionHealth.driver.lossRows"] = summary.DriverLossRows;
        metrics["events.collectionHealth.driver.lostCount"] = summary.DriverLostCount;
        metrics["events.collectionHealth.driver.queueDepth"] = summary.DriverQueueDepth;
        metrics["events.collectionHealth.driver.remainingUnread"] = summary.DriverRemainingUnread;
        metrics["events.collectionHealth.driver.drainStoppedAtDeadlineRows"] = summary.DriverDrainStoppedAtDeadlineRows;
        metrics["events.collectionHealth.driver.eventsSuppressed"] = summary.DriverEventsSuppressed;
        metrics["events.collectionHealth.driver.qualityWarningRows"] = summary.DriverQualityWarningRows;
        metrics["events.collectionHealth.process.treeUnavailable"] = summary.ProcessTreeUnavailable;
        metrics["events.collectionHealth.scheduledTask.captureFailed"] = summary.ScheduledTaskCaptureFailed;
        metrics["events.collectionHealth.pktmon.stopFailed"] = summary.PktmonStopFailed;
        metrics["events.collectionHealth.etw.decodeFailed"] = summary.EtwDecodeFailed;
    }

    private static bool IsHealthRow(SandboxEvent evt)
    {
        if (BoolTrue(evt, "collectionHealth", "collection_health", "collectionDiagnostic", "collectorDiagnostic", "collectorHealthEvidence"))
        {
            return true;
        }

        // R0 health rows can be emitted directly by the collector without a
        // normalized collectionHealth marker. Keep these rows in the quality
        // lane so queue state and bounded-drain evidence cannot disappear.
        if (IsDriverHealthRow(evt))
        {
            return true;
        }

        return IsLossRow(evt) ||
            IsProcessTreeUnavailable(evt) ||
            IsScheduledTaskCaptureFailed(evt) ||
            IsPktmonStopFailed(evt) ||
            IsEtwDecodeFailure(evt) ||
            TextContainsAny(evt.EventType, "capture_failed", "capture-failed", "capture_error", "capture-error");
    }

    private static bool IsFailureRow(SandboxEvent evt)
    {
        if (IsLossRow(evt) || IsProcessTreeUnavailable(evt) || IsScheduledTaskCaptureFailed(evt) ||
            IsPktmonStopFailed(evt) || IsEtwDecodeFailure(evt))
        {
            return true;
        }

        var type = evt.EventType ?? string.Empty;
        return TextContainsAny(type, "failed", "failure", "error", "unavailable", "missing") ||
            TextEqualsAny(Value(evt, "status", "captureState", "readinessState"), "failed", "failure", "error", "unavailable", "missing");
    }

    private static bool IsLossRow(SandboxEvent evt) => IsEtwLossRow(evt) || IsDriverLossRow(evt);

    private static bool IsEtwLossRow(SandboxEvent evt)
    {
        var source = Value(evt, "captureSource", "collectorSource", "source");
        var type = evt.EventType ?? string.Empty;
        var etwTagged = type.Contains("etw", StringComparison.OrdinalIgnoreCase) ||
            source.Contains("etw", StringComparison.OrdinalIgnoreCase);
        // EventsLost is emitted by ETW/tracerpt summaries without a stable
        // event type in some older agents. Keep the explicit counter even
        // when only its field name identifies the ETW lane, while leaving
        // cumulative driver TotalEventsLost in the driver lane.
        return PositiveData(evt, EtwLostKeys) && (etwTagged || (!IsDriverRow(evt) && !IsDriverHealthRow(evt)));
    }

    private static bool IsDriverLossRow(SandboxEvent evt)
    {
        if (IsDriverDeferredSummary(evt))
        {
            return AnyPositiveData(evt, "rawJsonlLostEventCount", "rawJsonlLossRowCount");
        }

        return IsDriverHealthRow(evt) && PositiveData(evt, DriverLostKeys);
    }

    private static bool IsDriverRow(SandboxEvent evt)
    {
        return IsR0DriverTelemetryRow(evt);
    }

    /// <summary>
    /// Identifies actual driver producer rows. ETW image.load rows and the
    /// guest-side driver.events.deferred summary are deliberately excluded;
    /// their evidence is accounted for in their own lanes.
    /// </summary>
    /// <summary>
    /// Returns whether an event is a driver producer row for coverage
    /// accounting. Source=driver image-load rows are real R0 telemetry; ETW
    /// image.load rows and the deferred guest summary are separate lanes.
    /// </summary>
    public static bool IsR0DriverTelemetryRow(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        if ((!type.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) &&
             !type.StartsWith("image.", StringComparison.OrdinalIgnoreCase)) ||
            string.Equals(type, "driver.events.deferred", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.Equals(evt.Source, "driver", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return string.Equals(Value(evt, "schema"), "ksword.sandbox.r0.event", StringComparison.OrdinalIgnoreCase) &&
            Value(evt, "eventOrigin").Contains("kernel-driver", StringComparison.OrdinalIgnoreCase) &&
            TextEqualsAny(Value(evt, "producerCategory"), "driver", "process", "image", "file", "registry", "network");
    }

    private static bool IsDriverHealthRow(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        return type.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.Source, "r0collector", StringComparison.OrdinalIgnoreCase) ||
            BoolTrue(evt, "collectorHealthEvidence");
    }

    private static bool IsDriverDeferredSummary(SandboxEvent evt) =>
        string.Equals(evt.EventType, "driver.events.deferred", StringComparison.OrdinalIgnoreCase);

    private static bool IsDrainStoppedAtDeadline(SandboxEvent evt) =>
        BoolTrue(evt, "drainStoppedAtDeadline", "drainStoppedAtDrainDeadline", "drainDeadlineReached", "deadlineReached");

    private static bool IsDriverQualityWarning(SandboxEvent evt)
    {
        return IsDrainStoppedAtDeadline(evt) ||
            PositiveData(evt, DriverQueueDepthKeys) ||
            PositiveData(evt, DriverRemainingUnreadKeys) ||
            PositiveData(evt, DriverSuppressedKeys) ||
            BoolTrue(evt, "backpressure", "backpressureObserved") ||
            IsDriverLossRow(evt);
    }

    private static bool IsProcessTreeUnavailable(SandboxEvent evt) =>
        string.Equals(evt.EventType, "process.tree_unavailable", StringComparison.OrdinalIgnoreCase);

    private static bool IsScheduledTaskCaptureFailed(SandboxEvent evt) =>
        string.Equals(evt.EventType, "scheduled_task.capture_failed", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(evt.EventType, "scheduled_task.capture-failed", StringComparison.OrdinalIgnoreCase);

    private static bool IsPktmonStopFailed(SandboxEvent evt) =>
        TextContainsAny(evt.EventType, "pktmonStopFailed") ||
        TextContainsAny(Value(evt, "failureReason", "reason", "diagnosticCode", "captureFailureReason"), "pktmonStopFailed");

    private static bool IsEtwDecodeFailure(SandboxEvent evt) =>
        string.Equals(evt.EventType, "etw_live.decode_failed", StringComparison.OrdinalIgnoreCase) ||
        (evt.EventType.Contains("etw", StringComparison.OrdinalIgnoreCase) &&
         (TextContainsAny(evt.EventType, "decode_failed", "decode-failed", "decode_error", "decode-error") ||
          TextEqualsAny(Value(evt, "decodeStatus", "decodeState", "decodeFailure"), "failed", "failure", "error")));

    private static string Value(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static bool PositiveData(SandboxEvent evt, IReadOnlyCollection<string> keys) =>
        keys.Any(key => ReadUnsigned(evt, key) > 0);

    private static bool AnyPositiveData(SandboxEvent evt, params string[] keys) =>
        keys.Any(key => ReadUnsigned(evt, key) > 0);

    private static ulong MaxDataUnsigned(IEnumerable<SandboxEvent> events, IReadOnlyCollection<string> keys)
    {
        return events
            .SelectMany(evt => keys.Select(key => ReadUnsigned(evt, key)))
            .DefaultIfEmpty()
            .Max();
    }

    private static ulong ReadUnsigned(SandboxEvent evt, string key)
    {
        if (evt.Data.TryGetValue(key, out var direct) && TryParseUnsigned(direct, out var number))
        {
            return number;
        }

        // tracerpt emits kernel logger metadata as one semicolon-delimited
        // payload field. Preserve EventsLost even when it is not promoted to
        // a standalone normalized Data key by the guest parser.
        if (evt.Data.TryGetValue("payload", out var payload))
        {
            foreach (var part in payload.Split(';'))
            {
                var separator = part.IndexOf('=');
                if (separator <= 0 || !string.Equals(part[..separator].Trim(), key, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return TryParseUnsigned(part[(separator + 1)..].Trim(), out number) ? number : 0UL;
            }
        }

        return 0UL;
    }

    private static bool TryParseUnsigned(string? value, out ulong number) =>
        ulong.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out number);

    private static bool BoolTrue(SandboxEvent evt, params string[] keys) =>
        keys.Any(key => evt.Data.TryGetValue(key, out var value) &&
            (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1"));

    private static bool TextEqualsAny(string value, params string[] values) =>
        values.Any(candidate => string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase));

    private static bool TextContainsAny(string value, params string[] values) =>
        values.Any(candidate => value.Contains(candidate, StringComparison.OrdinalIgnoreCase));

    private static int ToMetricInt(ulong value) => value > int.MaxValue ? int.MaxValue : (int)value;
}


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

    private static readonly string[] CollectorSuppressedKeys =
    [
        // Only explicit collector-side output suppression is actionable here.
        // Per-batch `suppressed` and `collectorSuppressedEvents` counters are
        // the intentional self-noise filter and must remain raw evidence
        // without degrading an otherwise drained capture.
        "eventsSuppressed"
    ];

    private static readonly string[] ProducerSuppressedMaskKeys =
    ["producerSuppressedMask", "producerSuppressedMaskHex"];

    private static readonly string[] ProducerEnableMaskKeys =
    ["effectiveProducerMask", "producerRuntimeEffectiveMask", "producerEnableMask"];

    private static readonly string[] ProducerSupportedMaskKeys =
    ["supportedProducerMask", "supportedProducerMaskHex"];

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
        // Keep the complete event context when classifying health rows. A
        // timed sample's process.exit lives in the health lane, while its
        // preceding process.timeout is a normal behavior row and is therefore
        // not present in `raw`; dropping that context would misclassify the
        // expected executor kill as an Agent failure.
        var failureRows = raw.Where(evt => IsFailureRow(evt, rawEvents)).ToList();
        var omitted = Math.Max(0, raw.Count - report.Count);
        var driverQueueDepth = MaxDataUnsigned(driverHealthRows, DriverQueueDepthKeys);
        // A startup POLL/GET_STATUS snapshot is not the unread tail at stop.
        // Only consume an explicit final/stopped summary (or an explicit
        // remainingUnread field from a batch summary); otherwise expose zero
        // plus a false Known flag so the report cannot claim the queue drained
        // or reuse the initial queue depth as "remaining".
        var finalRemainingRow = driverHealthRows
            .Where(HasExplicitRemainingUnread)
            .LastOrDefault();
        var driverQueueDepthAtStopKnown = finalRemainingRow is not null;
        var driverRemainingUnread = finalRemainingRow is null
            ? 0UL
            : FirstUnsigned(finalRemainingRow, DriverRemainingUnreadKeys);
        var malformedRows = raw.Count(IsMalformedDriverRow);
        var outputWriteFailureRows = raw.Count(IsOutputWriteFailureRow);
        var etwFailureRows = raw.Count(IsEtwFailure);
        var pcapFailureRows = raw.Count(IsPcapFailure);
        var agentFailureRows = raw.Count(evt => IsAgentFailure(evt, rawEvents));
        var processTreeUnavailableRows = raw.Count(evt => IsProcessTreeUnavailableFailure(evt, rawEvents));
        var expectedSuppressedRows = driverHealthRows.Count(HasExpectedProducerSuppression);
        var unexpectedSuppressedRows = driverHealthRows.Count(HasUnexpectedProducerSuppression);
        var unsupportedProducerRows = driverHealthRows.Count(HasUnsupportedProducerGap);
        var expectedSuppressedMask = MaxMask(driverHealthRows, ExpectedProducerSuppressedMask);
        var unexpectedSuppressedMask = MaxMask(driverHealthRows, UnexpectedProducerSuppressedMask);
        var unsupportedProducerMask = MaxMask(driverHealthRows, UnsupportedProducerMask);
        var collectorSuppressed = MaxDataUnsigned(driverHealthRows, CollectorSuppressedKeys);
        var stateReasons = BuildStateReasons(
            raw,
            driverHealthRows.Count,
            driverQueueDepthAtStopKnown,
            driverRemainingUnread,
            driverLossRows,
            malformedRows,
            outputWriteFailureRows,
            etwFailureRows,
            pcapFailureRows,
            agentFailureRows,
            collectorSuppressed,
            driverHealthRows.Count(IsDriverQualityWarning),
            expectedSuppressedRows,
            unsupportedProducerRows);

        return new CollectionHealthSummary
        {
            State = DetermineState(
                raw.Count,
                driverHealthRows.Count,
                driverQueueDepthAtStopKnown,
                driverRemainingUnread,
                driverLossRows.Count,
                malformedRows,
                outputWriteFailureRows,
                etwFailureRows,
                pcapFailureRows,
                agentFailureRows,
                collectorSuppressed,
                driverHealthRows.Count(IsDriverQualityWarning)),
            StateReasons = stateReasons,
            DriverHealthRows = driverHealthRows.Count,
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
            DriverQueueDepthAtStopKnown = driverQueueDepthAtStopKnown,
            DriverMalformedRows = malformedRows,
            DriverOutputWriteFailureRows = outputWriteFailureRows,
            DriverDrainStoppedAtDeadlineRows = driverHealthRows.Count(IsDrainStoppedAtDeadline),
            DriverEventsSuppressed = ToMetricInt(MaxDataUnsigned(driverHealthRows, DriverSuppressedKeys)),
            DriverExpectedSuppressedRows = expectedSuppressedRows,
            DriverUnexpectedSuppressedRows = unexpectedSuppressedRows,
            DriverUnsupportedProducerRows = unsupportedProducerRows,
            DriverExpectedSuppressedMask = ToMetricInt(expectedSuppressedMask),
            DriverUnexpectedSuppressedMask = ToMetricInt(unexpectedSuppressedMask),
            DriverUnsupportedProducerMask = ToMetricInt(unsupportedProducerMask),
            DriverQualityWarningRows = driverHealthRows.Count(IsDriverQualityWarning),
            ProcessTreeUnavailable = processTreeUnavailableRows,
            ScheduledTaskCaptureFailed = raw.Count(IsScheduledTaskCaptureFailed),
            PktmonStopFailed = raw.Count(IsPktmonStopFailed),
            EtwDecodeFailed = raw.Count(IsEtwDecodeFailure),
            EtwFailureRows = etwFailureRows,
            PcapFailureRows = pcapFailureRows,
            AgentFailureRows = agentFailureRows
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
        metrics["collectionHealth.stateCode"] = StateCode(summary.State);
        metrics["collectionHealth.complete"] = string.Equals(summary.State, "complete", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["collectionHealth.degraded"] = string.Equals(summary.State, "degraded", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["collectionHealth.partial"] = string.Equals(summary.State, "partial", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["collectionHealth.unknown"] = string.Equals(summary.State, "unknown", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["collectionHealth.driver.healthRows"] = summary.DriverHealthRows;
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
        metrics["collectionHealth.driver.queueDepthAtStopKnown"] = summary.DriverQueueDepthAtStopKnown ? 1 : 0;
        metrics["collectionHealth.driver.queueDepthAtStopUnknown"] = summary.DriverQueueDepthAtStopKnown ? 0 : 1;
        metrics["collectionHealth.driver.malformedRows"] = summary.DriverMalformedRows;
        metrics["collectionHealth.driver.outputWriteFailureRows"] = summary.DriverOutputWriteFailureRows;
        metrics["collectionHealth.driver.drainStoppedAtDeadlineRows"] = summary.DriverDrainStoppedAtDeadlineRows;
        metrics["collectionHealth.driver.eventsSuppressed"] = summary.DriverEventsSuppressed;
        metrics["collectionHealth.driver.expectedSuppressedRows"] = summary.DriverExpectedSuppressedRows;
        metrics["collectionHealth.driver.unexpectedSuppressedRows"] = summary.DriverUnexpectedSuppressedRows;
        metrics["collectionHealth.driver.unsupportedProducerRows"] = summary.DriverUnsupportedProducerRows;
        metrics["collectionHealth.driver.expectedSuppressedMask"] = summary.DriverExpectedSuppressedMask;
        metrics["collectionHealth.driver.unexpectedSuppressedMask"] = summary.DriverUnexpectedSuppressedMask;
        metrics["collectionHealth.driver.unsupportedProducerMask"] = summary.DriverUnsupportedProducerMask;
        metrics["collectionHealth.driver.qualityWarningRows"] = summary.DriverQualityWarningRows;
        metrics["collectionHealth.process.treeUnavailable"] = summary.ProcessTreeUnavailable;
        metrics["collectionHealth.scheduledTask.captureFailed"] = summary.ScheduledTaskCaptureFailed;
        metrics["collectionHealth.pktmon.stopFailed"] = summary.PktmonStopFailed;
        metrics["collectionHealth.etw.decodeFailed"] = summary.EtwDecodeFailed;
        metrics["collectionHealth.etw.failureRows"] = summary.EtwFailureRows;
        metrics["collectionHealth.pcap.failureRows"] = summary.PcapFailureRows;
        metrics["collectionHealth.agent.failureRows"] = summary.AgentFailureRows;
        metrics["runtime.collectionFailures"] = summary.FailureRows;
        metrics["runtime.failures"] = summary.FailureRows;
        metrics["events.runtime.collectionFailures"] = summary.FailureRows;
        metrics["events.runtime.failures"] = summary.FailureRows;

        // Metrics historically use an events.* namespace. Keep equivalent
        // aliases so report consumers can migrate from the flat health keys
        // without reparsing the raw diagnostic events.
        metrics["events.collectionHealth.raw"] = summary.RawRows;
        metrics["events.collectionHealth.stateCode"] = StateCode(summary.State);
        metrics["events.collectionHealth.complete"] = string.Equals(summary.State, "complete", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["events.collectionHealth.degraded"] = string.Equals(summary.State, "degraded", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["events.collectionHealth.partial"] = string.Equals(summary.State, "partial", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["events.collectionHealth.unknown"] = string.Equals(summary.State, "unknown", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        metrics["events.collectionHealth.driver.healthRows"] = summary.DriverHealthRows;
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
        metrics["events.collectionHealth.driver.queueDepthAtStopKnown"] = summary.DriverQueueDepthAtStopKnown ? 1 : 0;
        metrics["events.collectionHealth.driver.queueDepthAtStopUnknown"] = summary.DriverQueueDepthAtStopKnown ? 0 : 1;
        metrics["events.collectionHealth.driver.malformedRows"] = summary.DriverMalformedRows;
        metrics["events.collectionHealth.driver.outputWriteFailureRows"] = summary.DriverOutputWriteFailureRows;
        metrics["events.collectionHealth.driver.drainStoppedAtDeadlineRows"] = summary.DriverDrainStoppedAtDeadlineRows;
        metrics["events.collectionHealth.driver.eventsSuppressed"] = summary.DriverEventsSuppressed;
        metrics["events.collectionHealth.driver.expectedSuppressedRows"] = summary.DriverExpectedSuppressedRows;
        metrics["events.collectionHealth.driver.unexpectedSuppressedRows"] = summary.DriverUnexpectedSuppressedRows;
        metrics["events.collectionHealth.driver.unsupportedProducerRows"] = summary.DriverUnsupportedProducerRows;
        metrics["events.collectionHealth.driver.expectedSuppressedMask"] = summary.DriverExpectedSuppressedMask;
        metrics["events.collectionHealth.driver.unexpectedSuppressedMask"] = summary.DriverUnexpectedSuppressedMask;
        metrics["events.collectionHealth.driver.unsupportedProducerMask"] = summary.DriverUnsupportedProducerMask;
        metrics["events.collectionHealth.driver.qualityWarningRows"] = summary.DriverQualityWarningRows;
        metrics["events.collectionHealth.process.treeUnavailable"] = summary.ProcessTreeUnavailable;
        metrics["events.collectionHealth.scheduledTask.captureFailed"] = summary.ScheduledTaskCaptureFailed;
        metrics["events.collectionHealth.pktmon.stopFailed"] = summary.PktmonStopFailed;
        metrics["events.collectionHealth.etw.decodeFailed"] = summary.EtwDecodeFailed;
        metrics["events.collectionHealth.etw.failureRows"] = summary.EtwFailureRows;
        metrics["events.collectionHealth.pcap.failureRows"] = summary.PcapFailureRows;
        metrics["events.collectionHealth.agent.failureRows"] = summary.AgentFailureRows;
    }

    private static bool IsHealthRow(SandboxEvent evt)
    {
        if (IsRoutineR0ControlRow(evt))
        {
            // Empty per-batch control rows remain in driver-events.jsonl, but
            // do not consume report health rows or omission quota.
            return false;
        }

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
            IsMalformedDriverRow(evt) ||
            IsOutputWriteFailureRow(evt) ||
            IsProcessTreeUnavailable(evt) ||
            IsScheduledTaskCaptureFailed(evt) ||
            IsPktmonStopFailed(evt) ||
            IsEtwDecodeFailure(evt) ||
            IsEtwFailure(evt) ||
            IsPcapFailure(evt) ||
            IsAgentFailureCore(evt) ||
            TextContainsAny(evt.EventType, "capture_failed", "capture-failed", "capture_error", "capture-error");
    }

    private static bool IsRoutineR0ControlRow(SandboxEvent evt)
    {
        if (!string.Equals(evt.EventType, "r0collector.driverPoll", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(evt.EventType, "r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !IsDrainStoppedAtDeadline(evt) &&
            !PositiveData(evt, DriverRemainingUnreadKeys) &&
            !PositiveData(evt, DriverLostKeys) &&
            (!BoolTrue(evt, "backpressure", "backpressureObserved") || IsBenignRequestedMaxEventsBatchCap(evt)) &&
            !HasUnexpectedProducerSuppression(evt) &&
            !IsMalformedDriverRow(evt) &&
            !IsOutputWriteFailureRow(evt);
    }

    private static bool IsFailureRow(SandboxEvent evt, IReadOnlyCollection<SandboxEvent> raw)
    {
        // A process snapshot can legitimately miss a short-lived or already
        // exited process. Guest Agent marks this exact boundary with a stable
        // reason; keep it as diagnostics without inflating collection failure
        // counts. A process.tree_unavailable row remains a real gap.
        if (IsExpectedProcessSnapshotMiss(evt))
        {
            return false;
        }

        if (IsLossRow(evt) || IsProcessTreeUnavailableFailure(evt, raw) || IsScheduledTaskCaptureFailed(evt) ||
            IsPktmonStopFailed(evt) || IsEtwDecodeFailure(evt) ||
            IsEtwFailure(evt) || IsPcapFailure(evt) || IsAgentFailure(evt, raw) ||
            IsMalformedDriverRow(evt) || IsOutputWriteFailureRow(evt))
        {
            return true;
        }

        var type = evt.EventType ?? string.Empty;
        return TextContainsAny(type, "failed", "failure", "error", "unavailable", "missing") ||
            TextEqualsAny(Value(evt, "status", "captureState", "readinessState"), "failed", "failure", "error", "unavailable", "missing");
    }

    private static bool IsExpectedProcessSnapshotMiss(SandboxEvent evt)
    {
        return string.Equals(evt.EventType, "process.snapshot", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                Value(evt, "reason", "snapshotReason"),
                "processNotVisibleInCurrentSnapshot",
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLossRow(SandboxEvent evt) => IsEtwLossRow(evt) || IsDriverLossRow(evt);

    private static bool IsEtwLossRow(SandboxEvent evt)
    {
        var source = Value(evt, "captureSource", "collectorSource", "source");
        if (string.IsNullOrWhiteSpace(source))
        {
            source = evt.Source ?? string.Empty;
        }
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
             !type.StartsWith("image.", StringComparison.OrdinalIgnoreCase) &&
             !type.StartsWith("load.", StringComparison.OrdinalIgnoreCase)) ||
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
            TextEqualsAny(Value(evt, "producerCategory"), "driver", "process", "image", "file", "registry", "network", "load");
    }

    /// <summary>
    /// Returns whether a typed R0 row is attributed to the submitted sample.
    /// Keep this beside the producer-row predicate so raw/report coverage and
    /// attribution metrics cannot drift into different event sets.
    /// </summary>
    public static bool IsSampleAttributedR0DriverTelemetryRow(SandboxEvent evt)
    {
        if (!IsR0DriverTelemetryRow(evt))
        {
            return false;
        }

        return BoolTrue(evt, "behaviorCounted", "sampleBehaviorCandidate", "strongSampleCorrelation") ||
            AnyValueEqualsAny(evt, ["sampleCorrelation", "sampleCorrelationStatus", "evidenceDisposition"], "confirmed", "probable", "candidate", "correlated", "behavior-candidate", "sample-attributed");
    }

    /// <summary>
    /// Returns the stable coverage category for a typed driver row. The event
    /// type is preferred; producerCategory covers schema rows whose normalized
    /// type is generic. This is shared by raw and report metric builders.
    /// </summary>
    public static string GetR0DriverCategory(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        var suffix = type.StartsWith("driver.", StringComparison.OrdinalIgnoreCase)
            ? type["driver.".Length..]
            : type;
        var dot = suffix.IndexOf('.', StringComparison.Ordinal);
        var category = (dot >= 0 ? suffix[..dot] : suffix).ToLowerInvariant();
        if (category is not ("process" or "image" or "file" or "registry" or "network" or "load"))
        {
            var producerCategory = Value(evt, "producerCategory").ToLowerInvariant();
            category = producerCategory is "process" or "image" or "file" or "registry" or "network" or "load"
                ? producerCategory
                : "other";
        }

        return category;
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
        var benignRequestedMaxEventsBatchCap = IsBenignRequestedMaxEventsBatchCap(evt);

        // Per-batch poll/read rows are control-plane progress, not final
        // health summaries. Loss and unread counters are still counted by
        // their dedicated lanes below; keeping these rows out of the warning
        // count prevents routine self-noise filtering from degrading a clean
        // drained capture.
        var batchControlRow = string.Equals(evt.EventType, "r0collector.driverPoll", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase);
        if (batchControlRow &&
            !IsDrainStoppedAtDeadline(evt) &&
            !PositiveData(evt, DriverRemainingUnreadKeys) &&
            !IsDriverLossRow(evt) &&
            (!BoolTrue(evt, "backpressure", "backpressureObserved") || benignRequestedMaxEventsBatchCap) &&
            !IsMalformedDriverRow(evt) &&
            !IsOutputWriteFailureRow(evt))
        {
            return false;
        }

        // Point-in-time queueDepth/eventsQueued values describe collector
        // workload. They are not evidence of loss until an explicit final
        // unread tail, deadline, suppression, backpressure, or I/O failure.
        var finalUnread = HasExplicitRemainingUnread(evt) &&
            PositiveData(evt, DriverRemainingUnreadKeys);
        return IsDrainStoppedAtDeadline(evt) ||
            finalUnread ||
            PositiveData(evt, CollectorSuppressedKeys) ||
            HasUnexpectedProducerSuppression(evt) ||
            BoolTrue(evt, "backpressure", "backpressureObserved") ||
            IsDriverLossRow(evt) ||
            IsMalformedDriverRow(evt) ||
            IsOutputWriteFailureRow(evt);
    }

    private static bool IsBenignRequestedMaxEventsBatchCap(SandboxEvent evt)
    {
        // The driver can stop one read batch at the requested max-events
        // boundary while the queue continues draining. This is intentional
        // batching, not queue-full pressure, provided the batch reported no
        // dropped events. Keep this exception narrow to read-events rows so
        // other backpressure signals remain actionable.
        return string.Equals(evt.EventType, "r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase) &&
            BoolTrue(evt, "backpressure") &&
            TextEqualsAny(Value(evt, "backpressureReason"), "requested-max-events-reached") &&
            BoolTrue(evt, "cappedByMaxEvents") &&
            !PositiveData(evt, ["eventsDropped", "lostCount"]) &&
            !BoolTrue(evt, "lossObserved", "sequenceGapObserved", "outputBufferFull");
    }

    private static bool HasExpectedProducerSuppression(SandboxEvent evt) =>
        ExpectedProducerSuppressedMask(evt) != 0;

    private static bool HasUnexpectedProducerSuppression(SandboxEvent evt) =>
        UnexpectedProducerSuppressedMask(evt) != 0;

    private static bool HasUnsupportedProducerGap(SandboxEvent evt) =>
        UnsupportedProducerMask(evt) != 0;

    private static ulong ExpectedProducerSuppressedMask(SandboxEvent evt)
    {
        var suppressed = FirstUnsigned(evt, ProducerSuppressedMaskKeys);
        if (suppressed == 0)
        {
            return 0;
        }

        var enabled = FirstUnsigned(evt, ProducerEnableMaskKeys);
        return suppressed & ~enabled;
    }

    private static ulong UnexpectedProducerSuppressedMask(SandboxEvent evt)
    {
        var suppressed = FirstUnsigned(evt, ProducerSuppressedMaskKeys);
        if (suppressed == 0)
        {
            return 0;
        }

        var enabled = FirstUnsigned(evt, ProducerEnableMaskKeys);
        return suppressed & enabled;
    }

    private static ulong UnsupportedProducerMask(SandboxEvent evt)
    {
        var suppressed = FirstUnsigned(evt, ProducerSuppressedMaskKeys);
        var supported = FirstUnsigned(evt, ProducerSupportedMaskKeys);
        return suppressed & ~supported;
    }

    private static ulong MaxMask(IEnumerable<SandboxEvent> events, Func<SandboxEvent, ulong> selector) =>
        events.Select(selector).DefaultIfEmpty().Max();

    private static bool IsMalformedDriverRow(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        var category = Value(evt, "jsonlLineCategory", "jsonlImportStatus");
        return string.Equals(type, "driver.parse_error", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(type, "driver.read_error", StringComparison.OrdinalIgnoreCase) ||
            TextContainsAny(category, "malformed", "unreadable", "read-error") ||
            AnyPositiveData(evt, "rawJsonlMalformedLineCount") ||
            TextEqualsAny(Value(evt, "rawJsonlReadStatus"), "stream-summary-partial", "read-error");
    }

    private static bool IsOutputWriteFailureRow(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        var failureType = Value(evt, "failureType", "outputFailureType", "reason");
        var exitCode = Value(evt, "exitCode", "commandExitCode");
        return TextContainsAny(type, "outputWriteFailure", "output-write-failure") ||
            TextEqualsAny(failureType, "outputWriteFailure", "outputSpaceInsufficient", "outputOpenFailure") ||
            BoolTrue(evt, "outputWriteFailure", "driverOutputFailure") ||
            (string.Equals(type, "r0collector.failed", StringComparison.OrdinalIgnoreCase) &&
             (exitCode == "70" || exitCode.Equals("0x46", StringComparison.OrdinalIgnoreCase)));
    }

    private static bool HasExplicitRemainingUnread(SandboxEvent evt)
    {
        if (BoolTrue(evt, "queueDepthAtStopUnknown"))
        {
            return false;
        }

        // Older batch summaries use remainingUnread directly and are already
        // an explicit tail measurement. The newer collector status contract
        // also emits remainingQueueDepth on every snapshot, so that alias is
        // accepted only on a final/stopped marker.
        var directTailKeys = new[] { "remainingUnread", "remainingUnreadEvents", "remainingEvents" };
        if (directTailKeys.Any(key => evt.Data.ContainsKey(key) && TryParseUnsigned(evt.Data[key], out _)))
        {
            return true;
        }

        var finalMarker = string.Equals(evt.EventType, "r0collector.stopped", StringComparison.OrdinalIgnoreCase) ||
            TextEqualsAny(Value(evt, "statusPhase", "statusState"), "final", "stopped", "completed") ||
            BoolTrue(evt, "finalStatusAvailable", "drainQueueDrained");
        return finalMarker &&
            DriverRemainingUnreadKeys.Any(key => evt.Data.ContainsKey(key) && TryParseUnsigned(evt.Data[key], out _));
    }

    private static ulong FirstUnsigned(SandboxEvent evt, IReadOnlyCollection<string> keys)
    {
        foreach (var key in keys)
        {
            if (ReadUnsigned(evt, key) > 0 ||
                (evt.Data.TryGetValue(key, out var value) && TryParseUnsigned(value, out _)))
            {
                return ReadUnsigned(evt, key);
            }
        }

        return 0UL;
    }

    private static bool IsProcessTreeUnavailable(SandboxEvent evt) =>
        string.Equals(evt.EventType, "process.tree_unavailable", StringComparison.OrdinalIgnoreCase);

    private static bool IsProcessTreeUnavailableFailure(
        SandboxEvent evt,
        IReadOnlyCollection<SandboxEvent> raw)
    {
        if (!IsProcessTreeUnavailable(evt))
        {
            return false;
        }

        // After-run probes naturally observe a root after the executor has
        // terminated it. If the same PID already produced a process.tree or
        // process.snapshot row, the lineage was captured and this is an
        // expected terminal visibility transition rather than a collection
        // failure. Keep the unavailable row in raw evidence.
        return !raw.Any(other =>
            other.ProcessId == evt.ProcessId &&
            (string.Equals(other.EventType, "process.tree", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(other.EventType, "process.snapshot", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(other.EventType, "process.start", StringComparison.OrdinalIgnoreCase)) &&
            (string.IsNullOrWhiteSpace(evt.Path) || string.IsNullOrWhiteSpace(other.Path) ||
             string.Equals(evt.Path, other.Path, StringComparison.OrdinalIgnoreCase)) &&
            other.Timestamp <= evt.Timestamp);
    }

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

    private static bool IsEtwFailure(SandboxEvent evt)
    {
        if (!IsEtwTagged(evt))
        {
            return false;
        }

        return IsEtwDecodeFailure(evt) ||
            TextContainsAny(evt.EventType, "failed", "failure", "error", "unavailable") ||
            TextEqualsAny(Value(evt, "status", "captureState", "readinessState", "decodeStatus"), "failed", "failure", "error", "unavailable");
    }

    private static bool IsPcapFailure(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        var source = Value(evt, "captureSource", "collectorSource", "source");
        if (string.IsNullOrWhiteSpace(source))
        {
            source = evt.Source ?? string.Empty;
        }
        var pcapTagged = type.Contains("pcap", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("packet_capture", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("pktmon", StringComparison.OrdinalIgnoreCase) ||
            source.Contains("pcap", StringComparison.OrdinalIgnoreCase) ||
            source.Contains("pktmon", StringComparison.OrdinalIgnoreCase);
        if (!pcapTagged)
        {
            return false;
        }

        return IsPktmonStopFailed(evt) ||
            TextContainsAny(type, "failed", "failure", "error", "unavailable") ||
            TextEqualsAny(Value(evt, "status", "captureState", "readinessState"), "failed", "failure", "error", "unavailable");
    }

    private static bool IsAgentFailureCore(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        var source = Value(evt, "captureSource", "collectorSource", "source");
        if (string.IsNullOrWhiteSpace(source))
        {
            source = evt.Source ?? string.Empty;
        }
        var agentTagged = type.StartsWith("agent.", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("guest_agent", StringComparison.OrdinalIgnoreCase) ||
            source.Contains("agent", StringComparison.OrdinalIgnoreCase);
        if (!agentTagged)
        {
            return IsGuestSampleProcessExitFailure(evt);
        }

        if (TextContainsAny(type, "failed", "failure", "error", "unavailable"))
        {
            return true;
        }

        if (TextEqualsAny(Value(evt, "status", "captureState", "readinessState"), "failed", "failure", "error", "unavailable"))
        {
            return true;
        }

        var exitCode = Value(evt, "exitCode", "commandExitCode", "processExitCode");
        return TryParseNonZeroExitCode(exitCode);
    }

    private static bool IsAgentFailure(SandboxEvent evt, IReadOnlyCollection<SandboxEvent> raw)
    {
        return IsAgentFailureCore(evt) && !IsExpectedTimedSampleExit(evt, raw);
    }

    private static bool IsExpectedTimedSampleExit(SandboxEvent evt, IReadOnlyCollection<SandboxEvent> raw)
    {
        if (!string.Equals(evt.EventType, "process.exit", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(evt.Source, "guest", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return raw.Any(other =>
            string.Equals(other.EventType, "process.timeout", StringComparison.OrdinalIgnoreCase) &&
            other.ProcessId == evt.ProcessId &&
            (string.IsNullOrWhiteSpace(evt.Path) || string.IsNullOrWhiteSpace(other.Path) ||
             string.Equals(evt.Path, other.Path, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Guest Agent emits the submitted sample's terminal process row as
    /// process.exit, Source=guest. A CLR startup failure is represented as a
    /// signed HRESULT (for example -2146232576), so unsigned-only parsing
    /// would incorrectly leave the job in Completed/clean state.
    /// </summary>
    private static bool IsGuestSampleProcessExitFailure(SandboxEvent evt)
    {
        if (!string.Equals(evt.EventType, "process.exit", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var source = evt.Source ?? string.Empty;
        if (!string.Equals(source, "guest", StringComparison.OrdinalIgnoreCase) &&
            !source.Contains("guest-agent", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return TryParseNonZeroExitCode(Value(evt, "exitCode", "commandExitCode", "processExitCode"));
    }

    private static bool TryParseNonZeroExitCode(string value)
    {
        if (long.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var signed))
        {
            return signed != 0;
        }

        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            ulong.TryParse(value[2..], System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out var hex))
        {
            return hex != 0;
        }

        return false;
    }

    private static bool IsEtwTagged(SandboxEvent evt)
    {
        var type = evt.EventType ?? string.Empty;
        var source = Value(evt, "captureSource", "collectorSource", "source");
        if (string.IsNullOrWhiteSpace(source))
        {
            source = evt.Source ?? string.Empty;
        }
        return type.Contains("etw", StringComparison.OrdinalIgnoreCase) ||
            source.Contains("etw", StringComparison.OrdinalIgnoreCase);
    }

    private static string DetermineState(
        int rawRows,
        int driverHealthRows,
        bool queueDepthAtStopKnown,
        ulong remainingUnread,
        int driverLossRows,
        int malformedRows,
        int outputWriteFailureRows,
        int etwFailureRows,
        int pcapFailureRows,
        int agentFailureRows,
        ulong suppressedEvents,
        int qualityWarningRows)
    {
        if (rawRows == 0)
        {
            return "unknown";
        }

        var primaryGap = driverHealthRows == 0 ||
            !queueDepthAtStopKnown ||
            remainingUnread > 0 ||
            driverLossRows > 0 ||
            malformedRows > 0 ||
            outputWriteFailureRows > 0;
        if (primaryGap)
        {
            return "partial";
        }

        var optionalGap = etwFailureRows > 0 || pcapFailureRows > 0 || agentFailureRows > 0 ||
            suppressedEvents > 0 || qualityWarningRows > 0;
        return optionalGap ? "degraded" : "complete";
    }

    private static List<string> BuildStateReasons(
        IReadOnlyCollection<SandboxEvent> raw,
        int driverHealthRows,
        bool queueDepthAtStopKnown,
        ulong remainingUnread,
        IReadOnlyCollection<SandboxEvent> driverLossRows,
        int malformedRows,
        int outputWriteFailureRows,
        int etwFailureRows,
        int pcapFailureRows,
        int agentFailureRows,
        ulong suppressedEvents,
        int qualityWarningRows,
        int expectedSuppressedRows,
        int unsupportedProducerRows)
    {
        var reasons = new List<string>();
        if (raw.Count == 0)
        {
            reasons.Add("no-health-evidence");
            return reasons;
        }

        if (driverHealthRows == 0)
        {
            reasons.Add("driver-health-missing");
        }

        if (!queueDepthAtStopKnown)
        {
            reasons.Add("driver-final-queue-unknown");
        }

        if (remainingUnread > 0)
        {
            reasons.Add("driver-queue-not-drained");
        }

        if (driverLossRows.Count > 0)
        {
            reasons.Add("driver-loss");
        }

        if (malformedRows > 0)
        {
            reasons.Add("driver-malformed-jsonl");
        }

        if (outputWriteFailureRows > 0)
        {
            reasons.Add("driver-output-write-failure");
        }

        if (etwFailureRows > 0)
        {
            reasons.Add("etw-failure");
        }

        if (pcapFailureRows > 0)
        {
            reasons.Add("pcap-failure");
        }

        if (agentFailureRows > 0)
        {
            reasons.Add("agent-failure");
        }

        if (suppressedEvents > 0)
        {
            reasons.Add("driver-events-suppressed");
        }

        if (qualityWarningRows > 0)
        {
            reasons.Add("driver-quality-warning");
        }

        if (unsupportedProducerRows > 0)
        {
            // This is an explicit coverage gap, not a loss verdict. The raw
            // producer mask and suppression count remain visible in metrics
            // and the R0 evidence lane.
            reasons.Add("driver-unsupported-producer-gap");
        }

        if (expectedSuppressedRows > 0)
        {
            // The lane is intentionally disabled and its raw count remains
            // visible; this reason records the capability boundary without
            // downgrading a capture whose enabled producers drained cleanly.
            reasons.Add("driver-expected-disabled-producer");
        }

        return reasons;
    }

    private static int StateCode(string? state) => state?.ToLowerInvariant() switch
    {
        "complete" => 1,
        "degraded" => 2,
        "partial" => 3,
        _ => 0
    };

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

    private static bool AnyValueEqualsAny(SandboxEvent evt, IReadOnlyCollection<string> keys, params string[] values) =>
        keys.Any(key => evt.Data.TryGetValue(key, out var value) && TextEqualsAny(value, values));

    private static bool TextContainsAny(string value, params string[] values) =>
        values.Any(candidate => value.Contains(candidate, StringComparison.OrdinalIgnoreCase));

    private static int ToMetricInt(ulong value) => value > int.MaxValue ? int.MaxValue : (int)value;
}


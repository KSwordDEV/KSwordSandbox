using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Rules;

/// <summary>
/// Loads behavior rules and classifies normalized sandbox events.
/// Inputs are JSON rule files and SandboxEvent records, processing applies
/// deterministic exact-match, substring, regex, existence, and numeric-range
/// predicates, and methods return behavior findings.
/// </summary>
public sealed class RuleEngine
{
    private const int MaxEvidenceEventsPerRule = 50;

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private readonly BehaviorRuleSet ruleSet;

    /// <summary>
    /// Creates a rule engine for one immutable rule set.
    /// The input is a BehaviorRuleSet, processing stores it, and the
    /// constructor returns no value.
    /// </summary>
    public RuleEngine(BehaviorRuleSet ruleSet)
    {
        this.ruleSet = ruleSet;
    }

    /// <summary>
    /// Loads behavior rules from a JSON file.
    /// The input is a path to behavior-rules.json; processing deserializes it;
    /// the method returns a BehaviorRuleSet with an empty fallback.
    /// </summary>
    public static BehaviorRuleSet LoadRuleSet(string path)
    {
        if (!File.Exists(path))
        {
            return new BehaviorRuleSet();
        }

        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<BehaviorRuleSet>(json, JsonOptions) ?? new BehaviorRuleSet();
    }

    /// <summary>
    /// Applies all rules to the supplied event sequence.
    /// Inputs are normalized events, processing groups matching evidence by
    /// rule, and the method returns one finding per matched rule.
    /// </summary>
    public List<BehaviorFinding> Classify(IEnumerable<SandboxEvent> events)
    {
        var eventList = events.ToList();
        var findings = new List<BehaviorFinding>();

        foreach (var rule in ruleSet.Rules)
        {
            var evidence = new List<SandboxEvent>();
            var matchedCount = 0;
            foreach (var evt in eventList)
            {
                if (!Matches(rule, evt))
                {
                    continue;
                }

                matchedCount++;
                if (evidence.Count < MaxEvidenceEventsPerRule)
                {
                    evidence.Add(evt);
                }
            }

            if (matchedCount == 0)
            {
                continue;
            }

            var summary = rule.Summary;
            if (matchedCount > evidence.Count)
            {
                summary = string.IsNullOrWhiteSpace(summary)
                    ? $"Evidence shown: {evidence.Count} of {matchedCount} matching events."
                    : $"{summary} Evidence shown: {evidence.Count} of {matchedCount} matching events.";
            }

            findings.Add(new BehaviorFinding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Severity = rule.Severity,
                Confidence = rule.Confidence,
                Summary = summary,
                MitreTechniqueId = rule.MitreTechniqueId,
                MitreTechniqueName = rule.MitreTechniqueName,
                Tags = rule.Tags,
                Evidence = evidence
            });
        }

        return findings;
    }

    /// <summary>
    /// Tests whether one event satisfies one declarative rule.
    /// Inputs are a rule and event, processing checks event type, path,
    /// command-line, data-key, regex, numeric-range, existence, and all-of
    /// predicates; the method returns true on match.
    /// </summary>
    private static bool Matches(BehaviorRule rule, SandboxEvent evt)
    {
        if (rule.EventTypes.Count > 0 && !MatchesEventType(rule.EventTypes, evt.EventType))
        {
            return false;
        }

        if (rule.ContainsPath.Count > 0 && !ContainsAny(evt.Path, rule.ContainsPath))
        {
            return false;
        }

        if (rule.AllContainsPath.Count > 0 && !ContainsAll(evt.Path, rule.AllContainsPath))
        {
            return false;
        }

        if (rule.PathRegex.Count > 0 && !MatchesAnyRegex(evt.Path, rule.PathRegex))
        {
            return false;
        }

        if (rule.ContainsCommandLine.Count > 0 && !ContainsAny(evt.CommandLine, rule.ContainsCommandLine))
        {
            return false;
        }

        if (rule.AllContainsCommandLine.Count > 0 && !ContainsAll(evt.CommandLine, rule.AllContainsCommandLine))
        {
            return false;
        }

        if (rule.CommandLineRegex.Count > 0 && !MatchesAnyRegex(evt.CommandLine, rule.CommandLineRegex))
        {
            return false;
        }

        if (rule.DataKeys.Count > 0 && !rule.DataKeys.Any(key => HasRuleField(evt, key)))
        {
            return false;
        }

        if (rule.AllDataKeys.Count > 0 && !rule.AllDataKeys.All(key => HasRuleField(evt, key)))
        {
            return false;
        }

        if (rule.AbsentDataKeys.Count > 0 && rule.AbsentDataKeys.Any(key => HasRuleField(evt, key)))
        {
            return false;
        }

        if (rule.DataEquals.Count > 0 && !MatchesDataEquals(rule.DataEquals, evt))
        {
            return false;
        }

        if (rule.AllDataEquals.Count > 0 && !MatchesAllDataEquals(rule.AllDataEquals, evt))
        {
            return false;
        }

        if (rule.DataContains.Count > 0 && !MatchesDataContains(rule, evt))
        {
            return false;
        }

        if (rule.AllDataContains.Count > 0 && !MatchesAllDataContains(rule.AllDataContains, evt))
        {
            return false;
        }

        if (rule.DataContainsAll.Count > 0 && !MatchesDataContainsAll(rule.DataContainsAll, evt))
        {
            return false;
        }

        if (rule.DataRegex.Count > 0 && !MatchesDataRegex(rule.DataRegex, evt))
        {
            return false;
        }

        if (rule.AllDataRegex.Count > 0 && !MatchesAllDataRegex(rule.AllDataRegex, evt))
        {
            return false;
        }

        if (rule.DataNumericRanges.Count > 0 && !MatchesDataNumericRanges(rule.DataNumericRanges, evt))
        {
            return false;
        }

        if (rule.AllDataNumericRanges.Count > 0 && !MatchesAllDataNumericRanges(rule.AllDataNumericRanges, evt))
        {
            return false;
        }

        if (rule.ExcludeProcessNames.Count > 0 && MatchesProcessName(evt, rule.ExcludeProcessNames))
        {
            return false;
        }

        if (rule.ExcludePathContains.Count > 0 && ContainsAny(evt.Path, rule.ExcludePathContains))
        {
            return false;
        }

        if (rule.ExcludeCommandLineContains.Count > 0 && ContainsAny(evt.CommandLine, rule.ExcludeCommandLineContains))
        {
            return false;
        }

        if (rule.ExcludeDataEquals.Count > 0 && MatchesDataEquals(rule.ExcludeDataEquals, evt))
        {
            return false;
        }

        if (rule.ExcludeDataContains.Count > 0 && MatchesDataContains(rule.ExcludeDataContains, evt))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Tests whether an event data field contains configured text fragments.
    /// Inputs are a rule and event, processing checks each configured key with
    /// case-insensitive substring matching, and the method returns true when
    /// any key/fragments pair matches.
    /// </summary>
    private static bool MatchesDataContains(BehaviorRule rule, SandboxEvent evt)
    {
        return MatchesDataContains(rule.DataContains, evt);
    }

    /// <summary>
    /// Tests whether one event data dictionary exactly equals configured
    /// values. Inputs are a predicate dictionary and event, processing checks
    /// each key with case-insensitive exact matching, and the method returns
    /// true when any key/value pair matches.
    /// </summary>
    private static bool MatchesDataEquals(IReadOnlyDictionary<string, List<string>> dataEquals, SandboxEvent evt)
    {
        foreach (var (key, expectedValues) in dataEquals)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value))
            {
                continue;
            }

            if (expectedValues.Count == 0 ||
                expectedValues.Any(expected => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Tests whether every configured event data field exactly equals one of
    /// its configured values. Inputs are a predicate dictionary and event,
    /// processing applies case-insensitive exact matching per key, and the
    /// method returns true only when each key has a matching value.
    /// </summary>
    private static bool MatchesAllDataEquals(IReadOnlyDictionary<string, List<string>> allDataEquals, SandboxEvent evt)
    {
        foreach (var (key, expectedValues) in allDataEquals)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value))
            {
                return false;
            }

            if (expectedValues.Count > 0 &&
                !expectedValues.Any(expected => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Tests whether one event data dictionary contains configured fragments.
    /// Inputs are a predicate dictionary and event, processing checks each key
    /// with case-insensitive substring matching, and the method returns true
    /// when any key/fragments pair matches.
    /// </summary>
    private static bool MatchesDataContains(IReadOnlyDictionary<string, List<string>> dataContains, SandboxEvent evt)
    {
        foreach (var (key, fragments) in dataContains)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value))
            {
                continue;
            }

            if (fragments.Count == 0 || ContainsAny(value, fragments))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Tests whether every configured event data field contains one configured
    /// text fragment. Inputs are a predicate dictionary and event, processing
    /// checks each key with case-insensitive substring matching, and the
    /// method returns true only when all key/fragments pairs match.
    /// </summary>
    private static bool MatchesAllDataContains(IReadOnlyDictionary<string, List<string>> allDataContains, SandboxEvent evt)
    {
        foreach (var (key, fragments) in allDataContains)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value))
            {
                return false;
            }

            if (fragments.Count > 0 && !ContainsAny(value, fragments))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Tests whether every configured event data field contains every
    /// configured fragment. Inputs are a predicate dictionary and event,
    /// processing checks each field with case-insensitive substring matching,
    /// and the method returns true only when every field/fragments pair
    /// matches.
    /// </summary>
    private static bool MatchesDataContainsAll(IReadOnlyDictionary<string, List<string>> dataContainsAll, SandboxEvent evt)
    {
        foreach (var (key, fragments) in dataContainsAll)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value))
            {
                return false;
            }

            if (fragments.Count > 0 && !ContainsAll(value, fragments))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Tests whether one event data dictionary satisfies configured regular
    /// expressions. Inputs are a predicate dictionary and event, processing
    /// checks each key with case-insensitive regex matching and a timeout, and
    /// the method returns true when any key/pattern pair matches.
    /// </summary>
    private static bool MatchesDataRegex(IReadOnlyDictionary<string, List<string>> dataRegex, SandboxEvent evt)
    {
        foreach (var (key, patterns) in dataRegex)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value))
            {
                continue;
            }

            if (patterns.Count == 0 || MatchesAnyRegex(value, patterns))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Tests whether every configured event data field satisfies at least one
    /// configured regular expression. Inputs are a predicate dictionary and
    /// event, processing applies timeout-bound regex matching per key, and the
    /// method returns true only when all fields match.
    /// </summary>
    private static bool MatchesAllDataRegex(IReadOnlyDictionary<string, List<string>> allDataRegex, SandboxEvent evt)
    {
        foreach (var (key, patterns) in allDataRegex)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value))
            {
                return false;
            }

            if (patterns.Count > 0 && !MatchesAnyRegex(value, patterns))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Tests whether one event data dictionary satisfies configured numeric
    /// ranges. Inputs are a predicate dictionary and event, processing parses
    /// invariant-culture doubles, and the method returns true when any
    /// key/range pair matches.
    /// </summary>
    private static bool MatchesDataNumericRanges(
        IReadOnlyDictionary<string, List<BehaviorRuleNumericRange>> dataNumericRanges,
        SandboxEvent evt)
    {
        foreach (var (key, ranges) in dataNumericRanges)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value) || !TryParseNumber(value, out var numericValue))
            {
                continue;
            }

            if (ranges.Count == 0 || ranges.Any(range => ContainsNumber(range, numericValue)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Tests whether every configured event data field satisfies one configured
    /// numeric range. Inputs are a predicate dictionary and event, processing
    /// parses invariant-culture doubles, and the method returns true only when
    /// every configured key is present, numeric, and in range.
    /// </summary>
    private static bool MatchesAllDataNumericRanges(
        IReadOnlyDictionary<string, List<BehaviorRuleNumericRange>> allDataNumericRanges,
        SandboxEvent evt)
    {
        foreach (var (key, ranges) in allDataNumericRanges)
        {
            if (!TryGetRuleFieldValue(evt, key, out var value) || !TryParseNumber(value, out var numericValue))
            {
                return false;
            }

            if (ranges.Count > 0 && !ranges.Any(range => ContainsNumber(range, numericValue)))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Checks the normalized process name plus common image-name metadata.
    /// Inputs are one event and excluded names, processing compares exact base
    /// names with or without .exe suffix, and the method returns true on match.
    /// </summary>
    private static bool MatchesProcessName(SandboxEvent evt, IEnumerable<string> candidates)
    {
        var names = new List<string?>();
        names.Add(evt.ProcessName);
        foreach (var key in new[] { "processName", "imageName", "toolhelpImageName", "fileName", "name" })
        {
            if (evt.Data.TryGetValue(key, out var value))
            {
                names.Add(value);
            }
        }

        return names
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Any(name => candidates.Any(candidate => SameProcessName(name!, candidate)));
    }

    private static bool SameProcessName(string value, string candidate)
    {
        var normalizedValue = Path.GetFileName(value.Trim());
        var normalizedCandidate = Path.GetFileName(candidate.Trim());
        return string.Equals(normalizedValue, normalizedCandidate, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(TrimExe(normalizedValue), TrimExe(normalizedCandidate), StringComparison.OrdinalIgnoreCase);
    }

    private static string TrimExe(string value)
    {
        return value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? value[..^4]
            : value;
    }

    /// <summary>
    /// Checks exact string membership without case sensitivity.
    /// Inputs are candidate strings and one value, processing compares ordinal
    /// ignore-case, and the method returns true when a match exists.
    /// </summary>
    private static bool Contains(IEnumerable<string> candidates, string value)
    {
        return candidates.Any(candidate => string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks exact event-type membership plus bounded prefix wildcards.
    /// Inputs are configured event type names such as static.analysis.completed
    /// or static.* and one event type; processing allows only suffix-* prefix
    /// matches, and the method returns true when a candidate matches.
    /// </summary>
    private static bool MatchesEventType(IEnumerable<string> candidates, string value)
    {
        foreach (var candidate in candidates)
        {
            if (string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (candidate.EndsWith("*", StringComparison.Ordinal) &&
                candidate.Length > 1 &&
                value.StartsWith(candidate[..^1], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks whether text contains any configured substring.
    /// Inputs are nullable text and substrings, processing uses ordinal
    /// ignore-case search, and the method returns true when any substring hits.
    /// </summary>
    private static bool ContainsAny(string? text, IEnumerable<string> fragments)
    {
        return !string.IsNullOrEmpty(text)
            && fragments.Any(fragment => text.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks whether text contains every configured substring. Inputs are
    /// nullable text and substrings, processing uses ordinal ignore-case
    /// search, and the method returns true only when all substrings are found.
    /// </summary>
    private static bool ContainsAll(string? text, IEnumerable<string> fragments)
    {
        return !string.IsNullOrEmpty(text)
            && fragments.All(fragment => text.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks whether text satisfies any configured regular expression. Inputs
    /// are nullable text and regex patterns, processing uses culture-invariant
    /// case-insensitive matching with a bounded timeout, and the method returns
    /// false for empty text, invalid patterns, or timed-out patterns.
    /// </summary>
    private static bool MatchesAnyRegex(string? text, IEnumerable<string> patterns)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        foreach (var pattern in patterns)
        {
            try
            {
                if (Regex.IsMatch(
                    text,
                    pattern,
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                    RegexTimeout))
                {
                    return true;
                }
            }
            catch (ArgumentException)
            {
            }
            catch (RegexMatchTimeoutException)
            {
            }
        }

        return false;
    }

    private static bool TryParseNumber(string value, out double numericValue)
    {
        return double.TryParse(
                value,
                NumberStyles.Float,
                CultureInfo.InvariantCulture,
                out numericValue)
            && double.IsFinite(numericValue);
    }

    private static bool HasRuleField(SandboxEvent evt, string fieldName)
    {
        return TryGetRuleFieldValue(evt, fieldName, out _);
    }

    /// <summary>
    /// Resolves fields for advanced predicates. Inputs are an event and a
    /// field name, processing first checks SandboxEvent.Data and then stable
    /// top-level aliases, and the method returns true when a string value is
    /// available.
    /// </summary>
    private static bool TryGetRuleFieldValue(SandboxEvent evt, string fieldName, out string value)
    {
        if (evt.Data.TryGetValue(fieldName, out var directValue))
        {
            value = directValue;
            return true;
        }

        var normalized = fieldName.StartsWith("data.", StringComparison.OrdinalIgnoreCase)
            ? fieldName[5..]
            : fieldName;
        if (!string.Equals(normalized, fieldName, StringComparison.OrdinalIgnoreCase) &&
            evt.Data.TryGetValue(normalized, out var dataValue))
        {
            value = dataValue;
            return true;
        }

        value = normalized.ToLowerInvariant() switch
        {
            "eventtype" => evt.EventType,
            "source" => evt.Source,
            "processname" => evt.ProcessName ?? string.Empty,
            "processid" => evt.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            "parentprocessid" => evt.ParentProcessId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            "path" => evt.Path ?? string.Empty,
            "commandline" => evt.CommandLine ?? string.Empty,
            _ => string.Empty
        };

        return value.Length > 0;
    }

    private static bool ContainsNumber(BehaviorRuleNumericRange range, double numericValue)
    {
        if (range.Min is { } min)
        {
            var aboveMin = range.ExclusiveMin ? numericValue > min : numericValue >= min;
            if (!aboveMin)
            {
                return false;
            }
        }

        if (range.Max is { } max)
        {
            var belowMax = range.ExclusiveMax ? numericValue < max : numericValue <= max;
            if (!belowMax)
            {
                return false;
            }
        }

        return true;
    }
}

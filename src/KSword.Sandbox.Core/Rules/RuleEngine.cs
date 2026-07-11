using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Rules;

/// <summary>
/// Loads behavior rules and classifies normalized sandbox events.
/// Inputs are JSON rule files and SandboxEvent records, processing applies
/// deterministic exact-match and substring predicates, and methods return
/// behavior findings.
/// </summary>
public sealed class RuleEngine
{
    private const int MaxEvidenceEventsPerRule = 50;

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
    /// command-line, and data-key predicates; the method returns true on match.
    /// </summary>
    private static bool Matches(BehaviorRule rule, SandboxEvent evt)
    {
        if (rule.EventTypes.Count > 0 && !Contains(rule.EventTypes, evt.EventType))
        {
            return false;
        }

        if (rule.ContainsPath.Count > 0 && !ContainsAny(evt.Path, rule.ContainsPath))
        {
            return false;
        }

        if (rule.ContainsCommandLine.Count > 0 && !ContainsAny(evt.CommandLine, rule.ContainsCommandLine))
        {
            return false;
        }

        if (rule.DataKeys.Count > 0 && !rule.DataKeys.Any(evt.Data.ContainsKey))
        {
            return false;
        }

        if (rule.DataEquals.Count > 0 && !MatchesDataEquals(rule.DataEquals, evt))
        {
            return false;
        }

        if (rule.DataContains.Count > 0 && !MatchesDataContains(rule, evt))
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
            if (!evt.Data.TryGetValue(key, out var value))
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
    /// Tests whether one event data dictionary contains configured fragments.
    /// Inputs are a predicate dictionary and event, processing checks each key
    /// with case-insensitive substring matching, and the method returns true
    /// when any key/fragments pair matches.
    /// </summary>
    private static bool MatchesDataContains(IReadOnlyDictionary<string, List<string>> dataContains, SandboxEvent evt)
    {
        foreach (var (key, fragments) in dataContains)
        {
            if (!evt.Data.TryGetValue(key, out var value))
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
    /// Checks whether text contains any configured substring.
    /// Inputs are nullable text and substrings, processing uses ordinal
    /// ignore-case search, and the method returns true when any substring hits.
    /// </summary>
    private static bool ContainsAny(string? text, IEnumerable<string> fragments)
    {
        return !string.IsNullOrEmpty(text)
            && fragments.Any(fragment => text.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }
}

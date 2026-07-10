using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Rules;

/// <summary>
/// Loads behavior rules and classifies normalized sandbox events.
/// Inputs are JSON rule files and SandboxEvent records, processing applies
/// simple deterministic predicates, and methods return behavior findings.
/// </summary>
public sealed class RuleEngine
{
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
            var evidence = eventList.Where(evt => Matches(rule, evt)).ToList();
            if (evidence.Count == 0)
            {
                continue;
            }

            findings.Add(new BehaviorFinding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Severity = rule.Severity,
                Summary = rule.Summary,
                MitreTechniqueId = rule.MitreTechniqueId,
                MitreTechniqueName = rule.MitreTechniqueName,
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

        return true;
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

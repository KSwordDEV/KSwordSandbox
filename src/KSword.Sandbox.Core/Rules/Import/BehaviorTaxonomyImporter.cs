using System.Text.Json;
using KSword.Sandbox.Abstractions.Rules;

namespace KSword.Sandbox.Core.Rules.Import;

/// <summary>
/// Imports behavior taxonomy nodes from JSON files.
/// Inputs are JSON file paths; processing deserializes node arrays and records
/// diagnostics; methods return nodes plus any warnings or errors.
/// </summary>
public sealed class BehaviorTaxonomyImporter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>
    /// Imports taxonomy nodes from one file when it exists.
    /// The input is a JSON path, processing parses a node array defensively,
    /// and the method returns a RuleImportResult.
    /// </summary>
    public RuleImportResult Import(string path)
    {
        if (!File.Exists(path))
        {
            return new RuleImportResult
            {
                Diagnostics = [new RuleImportDiagnostic { SourcePath = path, Message = "Taxonomy file was not found.", IsError = true }]
            };
        }

        try
        {
            var nodes = JsonSerializer.Deserialize<List<BehaviorTaxonomyNode>>(File.ReadAllText(path), JsonOptions) ?? [];
            return new RuleImportResult { TaxonomyNodes = nodes };
        }
        catch (JsonException ex)
        {
            return new RuleImportResult
            {
                Diagnostics = [new RuleImportDiagnostic { SourcePath = path, Message = ex.Message, IsError = true }]
            };
        }
    }
}

using KSword.Sandbox.Abstractions.Rules;

namespace KSword.Sandbox.Core.Rules.Taxonomy;

/// <summary>
/// Holds behavior taxonomy nodes used to enrich rule output.
/// Inputs are taxonomy nodes from JSON or code defaults; processing indexes by
/// ID and event type; methods return matching nodes for classification.
/// </summary>
public sealed class BehaviorTaxonomy
{
    private readonly IReadOnlyList<BehaviorTaxonomyNode> nodes;

    /// <summary>
    /// Creates a taxonomy from node definitions.
    /// Inputs are taxonomy nodes, processing snapshots them into a list, and
    /// the constructor returns no value.
    /// </summary>
    public BehaviorTaxonomy(IEnumerable<BehaviorTaxonomyNode> nodes)
    {
        this.nodes = nodes.ToList();
    }

    /// <summary>
    /// Finds nodes that declare the supplied event type.
    /// The input is a normalized event type, processing compares case
    /// insensitively, and the method returns matching taxonomy nodes.
    /// </summary>
    public IReadOnlyList<BehaviorTaxonomyNode> FindByEventType(string eventType)
    {
        return nodes
            .Where(node => node.EventTypes.Any(type => string.Equals(type, eventType, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }
}

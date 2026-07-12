using KSword.Sandbox.Abstractions.Rules;

namespace KSword.Sandbox.Core.Rules.Taxonomy;

/// <summary>
/// Provides a minimal built-in taxonomy that can be expanded by JSON later.
/// Inputs are none; processing returns static node definitions; the method
/// returns behavior categories for early report enrichment.
/// </summary>
public static class DefaultBehaviorTaxonomy
{
    /// <summary>
    /// Creates the default behavior taxonomy.
    /// There are no inputs, processing materializes static nodes, and the
    /// method returns a BehaviorTaxonomy instance.
    /// </summary>
    public static BehaviorTaxonomy Create()
    {
        return new BehaviorTaxonomy(
        [
            new BehaviorTaxonomyNode
            {
                Id = "process-execution",
                Title = "Process execution",
                Category = "Execution",
                MitreTechniqueId = "T1059",
                EventTypes = ["process.start", "process.create"]
            },
            new BehaviorTaxonomyNode
            {
                Id = "file-drop",
                Title = "File creation or modification",
                Category = "File system",
                MitreTechniqueId = "T1105",
                EventTypes = ["file.created", "file.modified"]
            },
            new BehaviorTaxonomyNode
            {
                Id = "network-connect",
                Title = "Network connection",
                Category = "Command and Control",
                MitreTechniqueId = "T1071",
                EventTypes = ["network.tcp", "network.connect"]
            },
            new BehaviorTaxonomyNode
            {
                Id = "security-privilege-telemetry",
                Title = "Security and privilege telemetry",
                Category = "Privilege and security",
                MitreTechniqueId = "T1134",
                EventTypes = ["etw.security", "etw.privilege", "process.access", "privilege.enabled"]
            }
        ]);
    }
}

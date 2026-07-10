namespace KSword.Sandbox.SmokeTests.Framework;

/// <summary>
/// Runs smoke-test scenarios in a deterministic order.
/// Inputs are scenario instances and context; processing executes each scenario
/// sequentially; RunAsync returns a result list.
/// </summary>
internal sealed class SmokeTestSuite
{
    private readonly IReadOnlyList<ISmokeTestScenario> scenarios;

    /// <summary>
    /// Creates a smoke-test suite.
    /// The input is a scenario sequence, processing snapshots it, and the
    /// constructor returns no value.
    /// </summary>
    public SmokeTestSuite(IEnumerable<ISmokeTestScenario> scenarios)
    {
        this.scenarios = scenarios.ToList();
    }

    /// <summary>
    /// Runs all scenarios.
    /// Inputs are context and cancellation token, processing awaits each
    /// scenario, and the method returns all results.
    /// </summary>
    public async Task<IReadOnlyList<SmokeTestResult>> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var results = new List<SmokeTestResult>();
        foreach (var scenario in scenarios)
        {
            results.Add(await scenario.RunAsync(context, cancellationToken));
        }

        return results;
    }
}

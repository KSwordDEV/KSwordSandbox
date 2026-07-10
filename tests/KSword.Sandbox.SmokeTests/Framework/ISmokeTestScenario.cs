namespace KSword.Sandbox.SmokeTests.Framework;

/// <summary>
/// Defines an isolated smoke-test scenario.
/// Inputs are a shared SmokeTestContext and cancellation token; processing is
/// scenario-specific; RunAsync returns pass/fail metadata.
/// </summary>
internal interface ISmokeTestScenario
{
    string ScenarioId { get; }

    /// <summary>
    /// Executes the scenario.
    /// Inputs are test context and cancellation token, processing performs
    /// assertions, and the method returns a SmokeTestResult.
    /// </summary>
    Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default);
}

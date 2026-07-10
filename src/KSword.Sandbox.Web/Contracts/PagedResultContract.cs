namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: a materialized item page, offset, requested take count, and optional total count.
/// Processing: preserves pagination metadata separately from the actual item collection.
/// Return behavior: instances are serialized as API responses for list endpoints.
/// </summary>
/// <typeparam name="T">Item type contained in the page.</typeparam>
/// <param name="Items">Materialized page returned by endpoint or service code.</param>
/// <param name="Offset">Zero-based offset used to produce this page.</param>
/// <param name="Take">Requested maximum number of items in this page.</param>
/// <param name="Total">Optional total count when the source can calculate it cheaply.</param>
public sealed record PagedResultContract<T>(
    IReadOnlyList<T> Items,
    int Offset,
    int Take,
    int? Total)
{
    /// <summary>
    /// Gets the number of materialized items included in this page.
    /// </summary>
    public int Count => Items.Count;

    /// <summary>
    /// Inputs: the current page metadata.
    /// Processing: compares offset plus returned count against the optional total count.
    /// Return behavior: returns true when another page can be requested; otherwise false.
    /// </summary>
    public bool HasMore()
    {
        return Total.HasValue && Offset + Count < Total.Value;
    }

    /// <summary>
    /// Inputs: an enumerable source plus paging metadata produced by endpoint logic.
    /// Processing: materializes the enumerable once to avoid repeated enumeration during serialization.
    /// Return behavior: returns a stable paged response contract.
    /// </summary>
    public static PagedResultContract<T> From(IEnumerable<T> items, int offset, int take, int? total = null)
    {
        return new PagedResultContract<T>(items.ToArray(), offset, take, total);
    }
}

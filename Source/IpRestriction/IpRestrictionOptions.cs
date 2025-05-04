using Microsoft.Extensions.Logging;

namespace DNMH.Security.IpRestriction;

/// <summary>
/// Options for ip restriction.
/// </summary>
public sealed record IpRestrictionOptions
{
    /// <summary>
    /// Named restriction profiles keyed by name (e.g., "AdminPanel", "InternalApi").
    /// Can be used in <see cref="IpRestrictedAttribute"/> to specify which profile to use.
    /// </summary>
    public Dictionary<string, IpRangesOptions> Profiles { get; init; } = [];

    /// <summary>
    /// Global restrictions applied to all requests. 
    /// </summary>
    public IpRangesOptions Global { get; init; } = new();

    /// <summary>
    /// Log all denials (due to being in Deny list or missing from Allow list) using <see cref="ILogger"/>. Default is <see langword="false"/>.
    /// </summary>
    public bool LogDenials { get; init; } = false;
}

/// <summary>
/// Options for allow and deny a list of IP ranges.
/// </summary>
public sealed record IpRangesOptions
{
    /// <summary>
    /// List of IP ranges to allow.
    /// If a given IP address falls within both the Allow and Deny lists, the Deny list takes precedence.
    /// An empty list means allow all.
    /// </summary>
    /// <remarks>
    /// Supported IP range formats:
    /// <list type="bullet">
    ///   <item>
    ///     <description>
    ///       A single IP address (IPv4 or IPv6), e.g. <c>"127.0.0.1"</c> or <c>"::1"</c>
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       A network mask (only IPv4), e.g. <c>"192.168.0.0 255.255.0.0"</c>
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       A network CIDR/bitmask (IPv4 or IPv6), e.g. <c>"192.168.0.0/16" or "fd00::/8"</c>
    ///     </description>
    ///   </item>
    /// </list>
    /// </remarks>
    public IList<string> Allow { get; init; } = [];

    /// <summary>
    /// List of IP ranges to deny.
    /// If a given IP address falls within both the Allow and Deny lists, the Deny list takes precedence.
    /// An empty list means deny none.
    /// </summary>
    /// <remarks>
    /// Supported IP range formats:
    /// <list type="bullet">
    ///   <item>
    ///     <description>
    ///       A single IP address (IPv4 or IPv6), e.g. <c>"127.0.0.1"</c> or <c>"::1"</c>
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       A network mask (only IPv4), e.g. <c>"192.168.0.0 255.255.0.0"</c>
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       A network CIDR/bitmask (IPv4 or IPv6), e.g. <c>"192.168.0.0/16" or "fd00::/8"</c>
    ///     </description>
    ///   </item>
    /// </list>
    /// </remarks>
    public IList<string> Deny { get; init; } = [];
}

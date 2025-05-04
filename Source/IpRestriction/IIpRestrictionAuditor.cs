using System.Net;

namespace DNMH.Security.IpRestriction;

/// <summary>
/// Interface for auditing IP restrictions.
/// </summary>
internal interface IIpRestrictionAuditor
{
    /// <summary>
    /// Checks if the given IP address is allowed based on the provided <paramref name="profileKey"/> (if any) 
    /// and the <see cref="IpRestrictionOptions.Global"/> restrictions.
    /// </summary>
    bool IsIpAllowed(string? profileKey, IPAddress? remoteIpAddress);
}
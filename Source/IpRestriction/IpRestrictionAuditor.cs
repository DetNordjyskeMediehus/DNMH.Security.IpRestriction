using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Net;

namespace DNMH.Security.IpRestriction;

internal class IpRestrictionAuditor(IOptionsMonitor<IpRestrictionOptions> options, ILoggerFactory loggerFactory) : IIpRestrictionAuditor
{
    private ILogger<IpRestrictionAuditor> DenialLogger => options.CurrentValue.LogDenials ? loggerFactory.CreateLogger<IpRestrictionAuditor>() : NullLogger<IpRestrictionAuditor>.Instance;

    public bool IsIpAllowed(string? profileKey, IPAddress? remoteIpAddress)
    {
        if (remoteIpAddress is null)
        {
            DenialLogger.LogWarning("Request has no IP address, denying access.");
            return false;
        }

        // Get specific restriction profile if key is provided
        var profile = profileKey is { } key && options.CurrentValue.Profiles.TryGetValue(key, out var r) ? r : null;

        // Evaluate deny rules: if any deny match → deny immediately
        var combinedDeny = Combine(options.CurrentValue.Global.Deny, profile?.Deny).Select(x => IPNetwork2.Parse(x)).ToList();
        if (MatchesAny(combinedDeny, remoteIpAddress))
        {
            DenialLogger.LogInformation("IP {IP} denied by restriction rules.", remoteIpAddress);
            return false;
        }

        // Evaluate allow rules: if any allow lists exist, the IP must match at least one
        var allowLists = Combine(options.CurrentValue.Global.Allow, profile?.Allow).Select(x => IPNetwork2.Parse(x)).ToList();
        if (allowLists.Any() && !MatchesAny(allowLists, remoteIpAddress))
        {
            DenialLogger.LogInformation("IP {IP} is not in any allow list.", remoteIpAddress);
            return false;
        }

        return true;
    }

    private static bool MatchesAny(IEnumerable<IPNetwork2>? ranges, IPAddress ip) =>
        ranges?.Any(n => n.Contains(ip)) ?? false;

    private static IEnumerable<T> Combine<T>(IEnumerable<T>? a, IEnumerable<T>? b) =>
        (a ?? []).Concat(b ?? []);
}

using Microsoft.Extensions.Logging.Abstractions;
using System.Net;

namespace DNMH.Security.IpRestriction.Tests;

public class IpRestrictionAuditorTests
{
    private static readonly IPAddress AllowedIpv4 = IPAddress.Parse("10.0.0.1");
    private static readonly IPAddress DeniedIpv6 = IPAddress.Parse("2001:db8::223:14ff:feaa:6680");
    private static readonly IPAddress DeniedIpv4 = IPAddress.Parse("203.0.113.42");
    private static readonly IPAddress UnlistedIpv4 = IPAddress.Parse("192.168.99.99");

    [Fact]
    public void AllowsIpv4_WhenNoRules()
    {
        var options = new IpRestrictionOptions();

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed(null, AllowedIpv4).ShouldBeTrue();
    }

    [Fact]
    public void DeniesIpv4_WhenInGlobalDenyList()
    {
        var options = new IpRestrictionOptions
        {
            Global = new()
            {
                Deny = ["203.0.113.0/24"]
            }
        };

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed(null, DeniedIpv4).ShouldBeFalse();
        auditor.IsIpAllowed(null, AllowedIpv4).ShouldBeTrue();
    }

    [Fact]
    public void DeniesIpv6_WhenInGlobalDenyList()
    {
        var options = new IpRestrictionOptions
        {
            Global = new()
            {
                Deny = ["2001:db8::223:14ff:feaa:6680/64"]
            }
        };

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed(null, DeniedIpv6).ShouldBeFalse();
    }

    [Fact]
    public void DeniesIpv4_WhenInProfileDenyList()
    {
        var options = new IpRestrictionOptions
        {
            Profiles = new()
            {
                ["AdminPanel"] = new()
                {
                    Deny = ["203.0.113.0 255.255.255.0"]
                }
            }
        };

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed("AdminPanel", DeniedIpv4).ShouldBeFalse();
        auditor.IsIpAllowed("AdminPanel", AllowedIpv4).ShouldBeTrue();
    }

    [Fact]
    public void AllowsIpv4_WhenInAllowListAndNotInDenyList()
    {
        var options = new IpRestrictionOptions
        {
            Profiles = new()
            {
                ["AdminPanel"] = new()
                {
                    Allow = ["10.0.0.0/8"]
                }
            }
        };

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed("AdminPanel", AllowedIpv4).ShouldBeTrue();
        auditor.IsIpAllowed("AdminPanel", DeniedIpv4).ShouldBeFalse();
    }

    [Fact]
    public void DeniesIpv4_WhenAllowListExistsAndIpNotInIt()
    {
        var options = new IpRestrictionOptions
        {
            Profiles = new()
            {
                ["AdminPanel"] = new()
                {
                    Allow = ["10.0.0.0/8"]
                }
            }
        };

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed("AdminPanel", UnlistedIpv4).ShouldBeFalse();
    }

    [Fact]
    public void CombinesGlobalAndProfileAllowAndDenyListsIpv4()
    {
        var options = new IpRestrictionOptions
        {
            Global = new()
            {
                Allow = ["192.168.0.0/16"],
                Deny = ["203.0.113.0/24"]
            },
            Profiles = new()
            {
                ["SecureZone"] = new()
                {
                    Allow = ["10.0.0.0/8"],
                    Deny = ["198.51.100.0/24"]
                }
            }
        };

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);

        // Allowed by both global and profile allow list
        auditor.IsIpAllowed("SecureZone", AllowedIpv4).ShouldBeTrue();

        // Denied by global deny list
        auditor.IsIpAllowed("SecureZone", DeniedIpv4).ShouldBeFalse();

        // Denied by profile deny list
        auditor.IsIpAllowed("SecureZone", IPAddress.Parse("198.51.100.5")).ShouldBeFalse();

        // Not in allow lists, so denied
        auditor.IsIpAllowed("SecureZone", UnlistedIpv4).ShouldBeTrue();
    }
}

using Microsoft.Extensions.Logging.Abstractions;
using System.Net;

namespace DNMH.Security.IpRestriction.Tests;

public class IpRestrictionAuditorTests
{
    [Fact]
    public void AllowsIpv4_WhenNoRules()
    {
        var options = new IpRestrictionOptions();

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed(null, IPAddress.Parse("10.0.0.1")).ShouldBeTrue();
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
        auditor.IsIpAllowed(null, IPAddress.Parse("203.0.113.42")).ShouldBeFalse();
        auditor.IsIpAllowed(null, IPAddress.Parse("10.0.0.1")).ShouldBeTrue();
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
        auditor.IsIpAllowed(null, IPAddress.Parse("2001:db8::223:14ff:feaa:6680")).ShouldBeFalse();
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
        auditor.IsIpAllowed("AdminPanel", IPAddress.Parse("203.0.113.42")).ShouldBeFalse();
        auditor.IsIpAllowed("AdminPanel", IPAddress.Parse("10.0.0.1")).ShouldBeTrue();
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
        auditor.IsIpAllowed("AdminPanel", IPAddress.Parse("10.0.0.1")).ShouldBeTrue();
        auditor.IsIpAllowed("AdminPanel", IPAddress.Parse("203.0.113.42")).ShouldBeFalse();
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
        auditor.IsIpAllowed("AdminPanel", IPAddress.Parse("192.168.99.99")).ShouldBeFalse();
    }

    [Fact]
    public void AllowsIpv4_WhenProfileBroadensRange()
    {
        var options = new IpRestrictionOptions
        {
            Global = new()
            {
                Allow = ["10.0.0.0/24"]
            },
            Profiles = new()
            {
                ["AdminPanel"] = new()
                {
                    Allow = ["10.0.0.0/16"]
                }
            }
        };

        var auditor = new IpRestrictionAuditor(OptionsMonitor.Create(options), NullLoggerFactory.Instance);
        auditor.IsIpAllowed(null, IPAddress.Parse("10.0.0.0")).ShouldBeTrue();
        auditor.IsIpAllowed(null, IPAddress.Parse("10.0.1.0")).ShouldBeFalse();
        auditor.IsIpAllowed("AdminPanel", IPAddress.Parse("10.0.1.0")).ShouldBeTrue();
        auditor.IsIpAllowed("AdminPanel", IPAddress.Parse("10.1.0.0")).ShouldBeFalse();
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
        auditor.IsIpAllowed("SecureZone", IPAddress.Parse("10.0.0.1")).ShouldBeTrue();

        // Denied by global deny list
        auditor.IsIpAllowed("SecureZone", IPAddress.Parse("203.0.113.42")).ShouldBeFalse();

        // Denied by profile deny list
        auditor.IsIpAllowed("SecureZone", IPAddress.Parse("198.51.100.5")).ShouldBeFalse();

        // Not in allow lists, so denied
        auditor.IsIpAllowed("SecureZone", IPAddress.Parse("192.168.99.99")).ShouldBeTrue();
    }
}

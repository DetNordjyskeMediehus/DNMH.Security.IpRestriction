using Microsoft.Extensions.Options;
using System.Net;

namespace DNMH.Security.IpRestriction;

internal class IpRestrictionValidateOptions : IValidateOptions<IpRestrictionOptions>
{
    public ValidateOptionsResult Validate(string? name, IpRestrictionOptions options)
    {
        if (options.Profiles is null)
            return ValidateOptionsResult.Fail("Profiles for IP restrictions must not be null");

        if (options.Global is null)
            return ValidateOptionsResult.Fail("Global IP restrictions must not be null");

        var validationResults = 
            options.Profiles.Values.SelectMany(x => x.Allow)
            .Concat(options.Profiles.Values.SelectMany(x => x.Deny))
            .Concat(options.Global.Allow ?? [])
            .Concat(options.Global.Deny ?? [])
            .Select(ValidateIPNetwork);

        if (validationResults?.Any(x => x.Failed) ?? false)
        {
            return ValidateOptionsResult.Fail(
                $"Invalid IP network(s) in {nameof(IpRestrictionOptions)}: {string.Join(", ", validationResults.Where(x => x.Failed).Select(x => x.FailureMessage))}");
        }

        return ValidateOptionsResult.Success;
    }

    private static ValidateOptionsResult ValidateIPNetwork(string ipNetwork) => 
        IPNetwork2.TryParse(ipNetwork, out _) ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(ipNetwork);
}
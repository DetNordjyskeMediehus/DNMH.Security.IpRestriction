namespace DNMH.Security.IpRestriction;

/// <summary>
/// Restricts access to a controller or action method based on the IP address of the request.
/// </summary>
/// <param name="profileKey">The key of the profile in <see cref="IpRestrictionOptions.Profiles"/>.</param>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class IpRestrictedAttribute(string profileKey) : Attribute
{
    internal string Key { get; } = profileKey;
}

